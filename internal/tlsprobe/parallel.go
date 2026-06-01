package tlsprobe

import "sync"

func runParallelTasks(tasks ...func()) {
	var wg sync.WaitGroup
	wg.Add(len(tasks))
	for _, task := range tasks {
		go func(f func()) {
			defer wg.Done()
			f()
		}(task)
	}
	wg.Wait()
}
