package main

import (
	"log"
	"sort"
	"sync"
)

type TaskStatus int

const TaskAssigned TaskStatus = 0
const TaskCompleted TaskStatus = 1
const TaskReAssign TaskStatus = 2

// task managers cache all task it has assigned
// since the cost is trivial (batch number is limited)
type TaskAssigner struct {
	sync.Mutex
	notifier
	begin_with  uint64
	progress    uint64
	runingTasks map[uint64]TaskStatus
}

func construct(start uint64) *TaskAssigner {
	return &TaskAssigner{
		begin_with:  start,
		progress:    start,
		runingTasks: make(map[uint64]TaskStatus),
	}
}

func (t *TaskAssigner) setMessenger(url string) *TaskAssigner {
	t.Lock()
	defer t.Unlock()
	t.notifier = notifier(url)
	return t
}

func (t *TaskAssigner) assign_new() uint64 {

	t.Lock()
	defer t.Unlock()

	used := t.progress
	for tid, status := range t.runingTasks {
		if status == TaskReAssign {
			t.runingTasks[tid] = TaskAssigned
			return tid
		} else if tid >= used {
			used = tid + 1
		}
	}
	t.runingTasks[used] = TaskAssigned
	return used
}

func (t *TaskAssigner) drop(id uint64) {

	t.Lock()
	defer t.Unlock()

	for tid, status := range t.runingTasks {
		if tid == id {
			if status == TaskAssigned {
				t.runingTasks[tid] = TaskReAssign
			} else {
				log.Printf("unexpected dropping of completed task (%d)\n", id)
			}
			return
		}
	}
	log.Printf("unexpected dropping non-existed task (%d)\n", id)
}

func (t *TaskAssigner) reset(id uint64) {

	t.Lock()
	defer t.Unlock()
	t.runingTasks[id] = TaskReAssign
	log.Printf("enforce reset a task (%d)\n", id)
}

func (t *TaskAssigner) complete(id uint64) (bool, uint64) {
	t.Lock()
	defer t.Unlock()
	if _, existed := t.runingTasks[id]; !existed {
		log.Printf("unexpected completed task (%d)\n", id)
		return false, t.progress
	}
	t.runingTasks[id] = TaskCompleted

	// scan all tasks and make progress
	completed := []uint64{}
	nowProg := t.progress

	for id, status := range t.runingTasks {
		if status == TaskCompleted {
			completed = append(completed, id)
		}
	}

	sort.Slice(completed, func(i, j int) bool {
		return completed[i] < completed[j]
	})

	log.Printf("collect completed (%v), now %d\n", completed, t.progress)

	for _, id := range completed {
		if id == nowProg {
			delete(t.runingTasks, id)
			nowProg += 1
		} else if id > nowProg {
			break
		} else {
			panic("unexpected prog")
		}
	}

	defer func(newProg uint64) {
		t.progress = newProg
	}(nowProg)

	return nowProg > t.progress, nowProg
}

func (t *TaskAssigner) status() (result []uint64) {

	t.Lock()
	defer t.Unlock()

	for id, status := range t.runingTasks {
		if status != TaskCompleted {
			result = append(result, id)
		}
	}

	return
}
