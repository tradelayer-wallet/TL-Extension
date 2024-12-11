class ReadyPromise {
  constructor(count) {
    this.totalChecks = count;
    this.checked = 0;
    this.queue = [];
  }

  check() {
    this.checked += 1;
    if (this.checked === this.totalChecks) {
      this.processQueue();
    }
  }

  uncheck() {
    this.checked -= 1;
  }

  processQueue() {
    while (this.queue.length) {
      const task = this.queue.shift();
      task();
    }
  }

  call(task) {
    if (this.checked === this.totalChecks) {
      task();
    } else {
      this.queue.push(task);
    }
  }
}
