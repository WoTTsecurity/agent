import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Process
from multiprocessing import Queue
from typing import Callable
from typing import Dict
from typing import Any


class Executor():
    MAX_WORKERS = 10
    processes = MAX_WORKERS or os.cpu_count()
    executor = ThreadPoolExecutor(max_workers=processes)

    def __init__(self,
                 interval,
                 func, fargs,
                 timeout=None,
                 callback_timeout=None,
                 daemon=False,
                 debug=False):
        """
        Periodic process executor. Calls func and sleeps for interval,
        repeatedly. Kills the process after a timeout.
        Call schedule() to put it into asyncio loop.
        :param interval: sleep interval between calls, in seconds. If None, Executor will only execute once.
        :param func: the function to call
        :param fargs: function args (tuple) or a single arg
        :param timeout: kill the process after this many seconds
        :param callback_timeout: will be called if the process gets killed on timeout
        :param daemon:
        """
        self.interval = interval
        self.params = {'func': func, 'fn_args': fargs, "p_kwargs": {},
                       'timeout': timeout, 'callback_timeout': callback_timeout,
                       'daemon': daemon}
        self.process = None
        self.oneshot = interval is None
        self.should_stop = False
        self.debug = debug

    async def start(self):
        """ start calling the process periodically """
        while not self.should_stop:
            self.executor.submit(self._submit_unpack_kwargs, self.params)
            if self.oneshot:
                break
            await asyncio.sleep(self.interval)

    def stop(self):
        """ terminate running process """
        self.should_stop = True
        if self.process:
            self.process.terminate()

    def _submit_unpack_kwargs(self, params):
        """ unpack the kwargs and call submit """
        return self._submit(**params)

    def _submit(self,
                func: Callable,
                fn_args: Any,
                p_kwargs: Dict,
                timeout: float,
                callback_timeout: Callable[[Any], Any],
                daemon: bool):
        """
        Submits a callable to be executed with the given arguments.
        Schedules the callable to be executed as func(*args, **kwargs) in a new
         process.
        :param func: the function to execute
        :param fn_args: the arguments to pass to the function. Can be one argument
                or a tuple of multiple args.
        :param p_kwargs: the kwargs to pass to the function
        :param timeout: after this time, the process executing the function
                will be killed if it did not finish
        :param callback_timeout: this function will be called with the same
                arguments, if the task times out.
        :param daemon: run the child process as daemon
        :return: the result of the function, or None if the process failed or
                timed out
        """
        p_args = fn_args if isinstance(fn_args, tuple) else (fn_args,)
        queue = Queue()
        if self.debug:
            print("Executor: starting {} {}".format(func.__name__, p_args))
        p = Process(target=self._process_run,
                    args=(queue, func, *p_args,), kwargs=p_kwargs)

        if daemon:
            p.daemon = True
        self.process = p

        p.start()
        p.join(timeout=timeout)
        if not queue.empty():
            return queue.get()
        if callback_timeout:
            callback_timeout(*p_args, **p_kwargs)
        if p.is_alive():
            if self.debug:
                print('Executor: terminating by timeout')
            p.terminate()
            p.join()

    @staticmethod
    def _process_run(queue: Queue, func: Callable[[Any], Any] = None,
                     *args, **kwargs):
        """
        Executes the specified function as func(*args, **kwargs).
        The result will be stored in the shared dictionary
        :param func: the function to execute
        :param queue: a Queue
        """
        queue.put(func(*args, **kwargs))


def schedule(executor: Executor) -> asyncio.Future:
    """
    Put executor into asyncio loop.
    :param executor:
    :return: executor.start() wrapped in Future
    """
    return asyncio.ensure_future(executor.start())


def spin():
    asyncio.get_event_loop().run_forever()
