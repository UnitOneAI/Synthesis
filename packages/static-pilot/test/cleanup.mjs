// Node's after hooks run in registration order. Resource lifetimes need the
// reverse: close servers/databases before deleting the directories they use.
const stacks = new WeakMap();
export function cleanupAfter(t, dispose) {
  let stack = stacks.get(t);
  if (!stack) {
    stack = [];
    stacks.set(t, stack);
    t.after(async () => {
      const errors = [];
      while (stack.length) {
        try {
          await stack.pop()();
        } catch (error) {
          errors.push(error);
        }
      }
      if (errors.length) throw new AggregateError(errors, "Test resource cleanup failed");
    });
  }
  stack.push(dispose);
}
