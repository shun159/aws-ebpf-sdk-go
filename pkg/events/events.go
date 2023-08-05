// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
//limitations under the License.

package events

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	poller "github.com/aws/aws-ebpf-sdk-go/pkg/events/poll"
	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"golang.org/x/sys/unix"
)

var log = logger.Get()

type Events struct {
	RingBuffers          []*RingBuffer
	PageSize             int
	RingCnt              int
	stopRingBufferChan   chan struct{}
	updateRingBufferChan chan *RingBuffer
	eventsStopChannel    chan struct{}
	wg                   sync.WaitGroup
	eventsDataChannel    chan []byte

	epoller *poller.EventPoller
}

func isValidMapFDList(mapFDlist []int) bool {
	for _, mapFD := range mapFDlist {
		log.Infof("Got map FD %d", mapFD)
		if mapFD == -1 {
			return false
		}
		mapInfo, err := ebpf_maps.GetBPFmapInfo(mapFD)
		if err != nil {
			fmt.Errorf("failed to get map info")
			return false
		}
		if mapInfo.Type != constdef.BPF_MAP_TYPE_RINGBUF.Index() {
			fmt.Errorf("unsupported map type, should be - BPF_MAP_TYPE_RINGBUF")
			return false
		}
	}
	return true
}

func InitRingBuffer(mapFDlist []int) (map[int]chan []byte, error) {

	// Validate mapFD
	if !isValidMapFDList(mapFDlist) {
		return nil, fmt.Errorf("mapFDs passed to InitRingBuffer is invalid")
	}

	ev := &Events{
		PageSize: os.Getpagesize(),
		RingCnt:  0,
	}

	epoll, err := poller.NewEventPoller()
	if err != nil {
		return nil, fmt.Errorf("failed to create epoll instance: %s", err)
	}
	ev.epoller = epoll

	ringBufferChanList := make(map[int]chan []byte)
	for _, mapFD := range mapFDlist {

		mapInfo, err := ebpf_maps.GetBPFmapInfo(mapFD)
		if err != nil {
			fmt.Errorf("failed to get map info for mapFD %d", mapFD)
			return nil, fmt.Errorf("failed to map info")
		}

		eventsChan, err := ev.SetupRingBuffer(mapFD, mapInfo.MaxEntries)
		if err != nil {
			ev.CleanupRingBuffer()
			return nil, fmt.Errorf("failed to add ring buffer: %s", err)
		}

		log.Infof("Ringbuffer setup done for %d", mapFD)
		ringBufferChanList[mapFD] = eventsChan
	}
	return ringBufferChanList, nil
}

func (ev *Events) SetupRingBuffer(mapFD int, maxEntries uint32) (chan []byte, error) {
	ringbuffer := &RingBuffer{
		RingBufferMapFD: mapFD,
		Mask:            uint64(maxEntries - 1),
	}

	// [Consumer page - 4k][Producer page - 4k][Data section - twice the size of max entries]
	// Refer kernel code, twice the size of max entries will help in boundary scenarios
	// https://github.com/torvalds/linux/blob/master/kernel/bpf/ringbuf.c#L125

	consumer, err := unix.Mmap(mapFD, 0, ev.PageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to create Mmap for consumer -> %d: %s", mapFD, err)
	}

	ringbuffer.Consumerpos = unsafe.Pointer(&consumer[0])
	ringbuffer.Consumer = consumer

	mmap_sz := uint32(ev.PageSize) + 2*maxEntries
	producer, err := unix.Mmap(mapFD, int64(ev.PageSize), int(mmap_sz), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(producer)
		return nil, fmt.Errorf("failed to create Mmap for producer -> %d: %s", mapFD, err)
	}

	ringbuffer.Producerpos = unsafe.Pointer(&producer[0])
	ringbuffer.Producer = producer
	ringbuffer.Data = unsafe.Pointer(uintptr(unsafe.Pointer(&producer[0])) + uintptr(ev.PageSize))

	ev.RingBuffers = append(ev.RingBuffers, ringbuffer)
	ev.RingCnt++

	err = ev.epoller.AddEpollCtl(mapFD, ev.RingCnt)
	if err != nil {
		unix.Munmap(producer)
		return nil, fmt.Errorf("failed to Epoll event: %s", err)
	}

	//Start channels read
	ev.eventsStopChannel = make(chan struct{})
	ev.eventsDataChannel = make(chan []byte)

	ev.wg.Add(1)
	go ev.reconcileEventsDataChannel()
	return ev.eventsDataChannel, nil
}

func (ev *Events) CleanupRingBuffer() {

	for i := 0; i < ev.RingCnt; i++ {
		_ = unix.Munmap(ev.RingBuffers[i].Producer)
		_ = unix.Munmap(ev.RingBuffers[i].Consumer)
		ev.RingBuffers[i].Producerpos = nil
		ev.RingBuffers[i].Consumerpos = nil
	}

	if ev.epoller.GetEpollFD() >= 0 {
		_ = syscall.Close(ev.epoller.GetEpollFD())
	}
	ev.epoller = nil
	ev.RingBuffers = nil
	return
}

func (ev *Events) reconcileEventsDataChannel() {

	pollerCh := ev.epoller.EpollStart()
	defer func() {
		ev.wg.Done()
	}()

	for {
		select {
		case bufferPtr, ok := <-pollerCh:

			if !ok {
				return
			}
			ev.ReadRingBuffer(ev.RingBuffers[bufferPtr])

		case <-ev.eventsStopChannel:
			return
		}
	}
}

// Similar to libbpf poll ring
func (ev *Events) ReadRingBuffer(eventRing *RingBuffer) {
	readDone := true
	consPosition := eventRing.getConsumerPosition()
	for !readDone {
		readDone = ev.parseBuffer(consPosition, eventRing)
	}
}

func (ev *Events) parseBuffer(consumerPosition uint64, eventRing *RingBuffer) bool {
	readDone := true
	producerPosition := eventRing.getProducerPosition()
	for consumerPosition < producerPosition {

		// Get the header - Data points to the DataPage which will be offset by consumerPosition
		ringdata := eventRing.ParseRingData(consumerPosition)

		// Check if busy then skip, Might not be committed yet
		// There are 2 steps -> reserve and then commit/discard
		if ringdata.BusyRecord {
			readDone = true
			break
		}

		readDone = false

		// Update the position to the next record irrespective of discard or commit of data
		consumerPosition += uint64(ringdata.RecordLen)

		//Pick the data only if committed
		if !ringdata.DiscardRecord {
			ev.eventsDataChannel <- ringdata.parseSample()
		}
		eventRing.setConsumerPosition(consumerPosition)
	}
	return readDone
}