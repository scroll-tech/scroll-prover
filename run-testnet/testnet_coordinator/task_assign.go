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
	stop_assign bool
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

func (t *TaskAssigner) setMessenger(url string, id int) *TaskAssigner {
	t.Lock()
	defer t.Unlock()
	t.notifier = notifier{
		api:            url,
		coordinator_id: id,
	}
	return t
}

func (t *TaskAssigner) stopAssignment(stop bool) {
	t.Lock()
	defer t.Unlock()
	t.stop_assign = stop
}

func (t *TaskAssigner) isStopped() bool {

	t.Lock()
	defer t.Unlock()
	return t.stop_assign
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

func (t *TaskAssigner) status() (result []uint64, workRange [2]uint64) {

	t.Lock()
	defer t.Unlock()

	workRange[0] = t.progress
	workRange[1] = t.progress

	for id, status := range t.runingTasks {
		if status != TaskCompleted {
			result = append(result, id)
		}
		if id >= workRange[1] {
			workRange[1] = id
		}
	}

	return
}
