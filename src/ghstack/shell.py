#!/usr/bin/env python3

import asyncio
import logging
import os
import shlex
import subprocess
import sys
from typing import Any, Dict, IO, Optional, overload, Sequence, Tuple, TypeVar, Union

# Shell commands generally return str, but with exitcode=True
# they return a bool, and if stdout is piped straight to sys.stdout
# they return None.
_SHELL_RET = Union[bool, str, None]


_HANDLE = Union[None, int, IO[Any]]


def log_command(args: Sequence[str]) -> None:
    """
    Given a command, print it in a both machine and human readable way.

    Args:
        *args: the list of command line arguments you want to run
        env: the dictionary of environment variable settings for the command
    """
    cmd = " ".join(shlex.quote(arg) for arg in args)
    logging.info("$ " + cmd)


K = TypeVar("K")


V = TypeVar("V")


def merge_dicts(x: Dict[K, V], y: Dict[K, V]) -> Dict[K, V]:
    z = x.copy()
    z.update(y)
    return z


class Shell(object):
    """
    An object representing a shell (e.g., the bash prompt in your
    terminal), maintaining a concept of current working directory, and
    also the necessary accoutrements for testing.
    """

    # Current working directory of shell.
    cwd: str

    # Whether or not to suppress printing of command executed.
    quiet: bool

    # Whether or not shell is in testing mode; some commands are made
    # more deterministic in this case.
    testing: bool

    # The current Unix timestamp.  Only used during testing mode.
    testing_time: int

    def __init__(
        self, quiet: bool = False, cwd: Optional[str] = None, testing: bool = False
    ):
        """
        Args:
            cwd: Current working directory of the shell.  Pass None to
                initialize to the current cwd of the current process.
            quiet: If True, suppress printing out the command executed
                by the shell.  By default, we print out commands for ease
                of debugging.  Quiet is most useful for non-mutating
                shell commands.
            testing: If True, operate in testing mode.  Testing mode
                enables features which make the outputs of commands more
                deterministic; e.g., it sets a number of environment
                variables for Git.
        """
        self.cwd = cwd if cwd else os.getcwd()
        self.quiet = quiet
        self.testing = testing
        self.testing_time = 1112911993

    def sh(
        self,
        *args: str,  # noqa: C901
        env: Optional[Dict[str, str]] = None,
        stderr: _HANDLE = None,
        # TODO: Arguably bytes should be accepted here too
        input: Optional[str] = None,
        stdin: _HANDLE = None,
        stdout: _HANDLE = subprocess.PIPE,
        exitcode: bool = False,
        tick: bool = False,
    ) -> _SHELL_RET:
        """
        Run a command specified by args, and return string representing
        the stdout of the run command, raising an error if exit code
        was nonzero (unless exitcode kwarg is specified; see below).

        Args:
            *args: the list of command line arguments to run
            env: any extra environment variables to set when running the
                command.  Environment variables set this way are ADDITIVE
                (unlike subprocess default)
            stderr: where to pipe stderr; by default, we pipe it straight
                to this process's stderr
            input: string value to pass stdin.  This is mutually exclusive
                with stdin
            stdin: where to pipe stdin from.  This is mutually exclusive
                with input
            stdout: where to pipe stdout; by default, we capture the stdout
                and return it
            exitcode: if True, return a bool rather than string, specifying
                whether or not the process successfully returned with exit
                code 0.  We never raise an exception when this is True.
        """
        assert not (stdin and input)
        if tick:
            self.test_tick()
        if input:
            stdin = subprocess.PIPE
        if not self.quiet:
            log_command(args)
        if env is not None:
            env = merge_dicts(dict(os.environ), env)

        # The things we do for logging...
        #
        # - I didn't make a PTY, so programs are going to give
        #   output assuming there isn't a terminal at the other
        #   end.  This is less nice for direct terminal use, but
        #   it's better for logging (since we get to dispense
        #   with the control codes).
        #
        # - We assume line buffering.  This is kind of silly but
        #   we need to assume *some* sort of buffering with the
        #   stream API.

        async def process_stream(
            proc_stream: asyncio.StreamReader, setting: _HANDLE, default_stream: IO[str]
        ) -> bytes:
            output = []
            while True:
                try:
                    line = await proc_stream.readuntil()
                except asyncio.LimitOverrunError as e:
                    line = await proc_stream.readexactly(e.consumed)
                except asyncio.IncompleteReadError as e:
                    line = e.partial
                if not line:
                    break
                output.append(line)
                if setting == subprocess.PIPE:
                    pass
                elif setting == subprocess.STDOUT:
                    sys.stdout.buffer.write(line)
                elif isinstance(setting, int):
                    os.write(setting, line)
                elif setting is None:
                    # Sigh.  See https://stackoverflow.com/questions/55681488/python-3-write-binary-to-stdout-respecting-buffering
                    default_stream.write(line.decode("utf-8"))
                else:
                    # NB: don't use setting.write directly, that will
                    # not properly handle binary.  This gives us
                    # "parity" with the normal subprocess implementation
                    os.write(setting.fileno(), line)
            return b"".join(output)

        async def feed_input(stdin_writer: Optional[asyncio.StreamWriter]) -> None:
            if stdin_writer is None:
                return
            if not input:
                return
            stdin_writer.write(input.encode("utf-8"))
            await stdin_writer.drain()
            stdin_writer.close()

        async def run() -> Tuple[int, bytes, bytes]:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=stdin,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.cwd,
                env=env,
            )
            assert proc.stdout is not None
            assert proc.stderr is not None
            _, out, err, _ = await asyncio.gather(
                feed_input(proc.stdin),
                process_stream(proc.stdout, stdout, sys.stdout),
                process_stream(proc.stderr, stderr, sys.stderr),
                proc.wait(),
            )
            assert proc.returncode is not None
            return (proc.returncode, out, err)

        loop = asyncio.get_event_loop()
        returncode, out, err = loop.run_until_complete(run())

        def decode(b: bytes) -> str:
            return (
                b.decode(errors="backslashreplace")
                .replace("\0", "\\0")
                .replace("\r\n", "\n")
            )

        # NB: Not debug; we always want to show this to user.
        if err:
            logging.debug("# stderr:\n" + decode(err))
        if out:
            logging.debug(("# stdout:\n" if err else "") + decode(out))

        if exitcode:
            logging.debug("Exit code: {}".format(returncode))
            return returncode == 0
        if returncode != 0:
            raise RuntimeError(
                "{} failed with exit code {}".format(" ".join(args), returncode)
            )

        if stdout == subprocess.PIPE:
            return out.decode()  # do a strict decode for actual return
        else:
            return None

    def _maybe_rstrip(self, s: _SHELL_RET) -> _SHELL_RET:
        if isinstance(s, str):
            return s.rstrip()
        else:
            return s

    @overload  # noqa: F811
    def git(self, *args: str) -> str: ...

    @overload  # noqa: F811
    def git(self, *args: str, input: str) -> str: ...

    @overload  # noqa: F811
    def git(self, *args: str, input: str, env: Dict[str, str]) -> str: ...

    @overload  # noqa: F811
    def git(self, *args: str, **kwargs: Any) -> _SHELL_RET: ...

    def git(self, *args: str, **kwargs: Any) -> _SHELL_RET:  # noqa: F811
        """
        Run a git command.  The returned stdout has trailing newlines stripped.

        Args:
            *args: Arguments to git
            **kwargs: Any valid kwargs for sh()
        """
        env = kwargs.setdefault("env", {})
        # For git hooks to detect execution inside ghstack
        env.setdefault("GHSTACK", "1")
        # For dealing with https://github.com/ezyang/ghstack/issues/174
        env.setdefault(
            "GIT_TERMINAL_PROMPT", os.environ.get("GIT_TERMINAL_PROMPT", "0")
        )
        # Some envvars to make things a little more script mode nice
        if self.testing:
            env.setdefault("EDITOR", ":")
            env.setdefault("GIT_MERGE_AUTOEDIT", "no")
            env.setdefault("LANG", "C")
            env.setdefault("LC_ALL", "C")
            env.setdefault("PAGER", "cat")
            env.setdefault("TZ", "UTC")
            env.setdefault("TERM", "dumb")
            # These are important so we get deterministic commit times
            env.setdefault("GIT_AUTHOR_EMAIL", "author@example.com")
            env.setdefault("GIT_AUTHOR_NAME", "A U Thor")
            env.setdefault("GIT_COMMITTER_EMAIL", "committer@example.com")
            env.setdefault("GIT_COMMITTER_NAME", "C O Mitter")
            env.setdefault("GIT_COMMITTER_DATE", "{} -0700".format(self.testing_time))
            env.setdefault("GIT_AUTHOR_DATE", "{} -0700".format(self.testing_time))
            if "stderr" not in kwargs:
                kwargs["stderr"] = subprocess.PIPE

        return self._maybe_rstrip(self.sh(*(("git",) + args), **kwargs))

    @overload  # noqa: F811
    def hg(self, *args: str) -> str: ...

    @overload  # noqa: F811
    def hg(self, *args: str, input: str) -> str: ...

    @overload  # noqa: F811
    def hg(self, *args: str, **kwargs: Any) -> _SHELL_RET: ...

    def hg(self, *args: str, **kwargs: Any) -> _SHELL_RET:  # noqa: F811
        """
        Run a hg command.  The returned stdout has trailing newlines stripped.

        Args:
            *args: Arguments to hg
            **kwargs: Any valid kwargs for sh()
        """

        return self._maybe_rstrip(self.sh(*(("hg",) + args), **kwargs))

    def jf(self, *args: str, **kwargs: Any) -> _SHELL_RET:
        """
        Run a jf command.  The returned stdout has trailing newlines stripped.

        Args:
            *args: Arguments to jf
            **kwargs: Any valid kwargs for sh()
        """

        kwargs.setdefault("stdout", sys.stderr)

        return self._maybe_rstrip(self.sh(*(("jf",) + args), **kwargs))

    def test_tick(self) -> None:
        """
        Increase the current time.  Useful when testing is True.
        """
        self.testing_time += 60

    def open(self, fn: str, mode: str) -> IO[Any]:
        """
        Open a file, relative to the current working directory.

        Args:
            fn: filename to open
            mode: mode to open the file as
        """
        return open(os.path.join(self.cwd, fn), mode)

    def cd(self, d: str) -> None:
        """
        Change the current working directory.

        Args:
            d: directory to change to
        """
        self.cwd = os.path.join(self.cwd, d)
