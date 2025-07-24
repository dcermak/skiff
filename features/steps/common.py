from pathlib import Path
import re
import behave
import shlex
import subprocess


def check_exit_code(context):
    """Check if the previous command finished successfully or if the exit code
    was tested in a scenario.

    """
    if not getattr(context, "cmd", None):
        return

    if context.cmd_exitcode_checked:
        return

    the_exit_code_is(context, 0)


@behave.step('I run skiff with the subcommand "{cmd}"')
def step_impl(context, cmd: str) -> None:
    check_exit_code(context)

    skiff = Path(__file__).absolute().parent.parent.parent / "bin" / "skiff"

    run_in_context(context, (str(skiff), *shlex.split(cmd)), can_fail=True)


@behave.step("I run podman {cmd}")
def step_impl(context, cmd: str) -> None:
    check_exit_code(context)
    run_in_context(context, ("podman", *shlex.split(cmd)), can_fail=True)


def run_in_context(
    context, cmd: tuple[str, ...] | list[str], can_fail=False, **run_args
):
    check_exit_code(context)

    context.cmd = cmd

    res = subprocess.run(cmd, capture_output=True, **run_args)
    context.cmd_exitcode, context.cmd_stdout, context.cmd_stderr = (
        res.returncode,
        res.stdout.decode(),
        res.stderr.decode(),
    )
    context.cmd_exitcode_checked = False

    if not can_fail and context.cmd_exitcode != 0:
        raise AssertionError(
            'Running command "%s" failed: %s' % (cmd, context.cmd_exitcode)
        )


@behave.step("the exit code is {exitcode}")
def the_exit_code_is(context, exitcode):
    if context.cmd_exitcode != int(exitcode):
        lines = [
            f"Command has exited with code {context.cmd_exitcode}: {context.cmd}",
            "> stdout:",
            context.cmd_stdout.strip(),
            "",
            "> stderr:",
            context.cmd_stderr.strip(),
        ]
        raise AssertionError("\n".join(lines))
    context.cmd_exitcode_checked = True


@behave.step("stderr contains")
def step_impl(context):
    expected = context.text.format(context=context).rstrip()
    found = context.cmd_stderr.rstrip()

    if re.search(expected, found, re.MULTILINE):
        return

    raise AssertionError(
        f"Stderr doesn't contain:\n{expected}\n\nActual stderr:\n{found}"
    )


@behave.step("stdout contains")
def step_impl(context):
    expected = context.text.format(context=context).rstrip()
    found = context.cmd_stdout.rstrip()

    if re.search(expected, found, re.MULTILINE):
        return

    raise AssertionError(
        f"Stdout doesn't contain:\n{expected}\n\nActual stdout:\n{found}"
    )


@behave.step("stdout is")
def step_impl(context):
    expected = context.text.format(context=context).strip()
    found = context.cmd_stdout.strip()

    if expected != found:
        raise AssertionError(
            f"Stdout doesn't equal:\n{expected}\n\nActual stdout:\n{found}"
        )


@behave.step("stderr is")
def step_impl(context):
    expected = context.text.format(context=context).strip()
    found = context.cmd_stderr.strip()

    if expected != found:
        raise AssertionError(
            f"Stderr doesn't equal:\n{expected}\n\nActual stderr:\n{found}"
        )
