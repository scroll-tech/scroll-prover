package main

import (
	"log"
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
	begin_with  uint64
	runingTasks map[uint64]TaskStatus
}

func construct(start uint64) *TaskAssigner {
	return &TaskAssigner{
		begin_with:  start,
		runingTasks: make(map[uint64]TaskStatus),
	}
}

func (t *TaskAssigner) assign_new() uint64 {

	t.Lock()
	defer t.Unlock()

	used := t.begin_with
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

func (t *TaskAssigner) complete(id uint64) {
	t.Lock()
	defer t.Unlock()
	t.runingTasks[id] = TaskCompleted

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
