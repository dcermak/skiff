from pathlib import Path
import re
import behave
import shlex
import subprocess
import tempfile
import os
import time


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

    # Replace {temp_dir} with the actual temporary directory
    if hasattr(context, "temp_dir"):
        cmd = cmd.replace("{temp_dir}", context.temp_dir)

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


@behave.step("I create a temporary directory for mounting")
def step_impl(context):
    check_exit_code(context)
    context.temp_dir = tempfile.mkdtemp(prefix="skiff_mount_test_")


@behave.step('I run "{cmd}"')
def step_impl(context, cmd: str) -> None:
    check_exit_code(context)

    # Replace {temp_dir} with the actual temporary directory
    if hasattr(context, "temp_dir"):
        cmd = cmd.replace("{temp_dir}", context.temp_dir)

    run_in_context(context, shlex.split(cmd), can_fail=True)


@behave.step('I run skiff with the subcommand "{cmd}" in the background')
def step_impl(context, cmd: str) -> None:
    check_exit_code(context)

    # Fail if there's already a background process
    background_proc = getattr(context, "background_proc", None)
    if background_proc and background_proc.poll() is None:
        raise RuntimeError("A background process is already running")

    # Replace {temp_dir} with the actual temporary directory
    if hasattr(context, "temp_dir"):
        cmd = cmd.replace("{temp_dir}", context.temp_dir)

    skiff = Path(__file__).absolute().parent.parent.parent / "bin" / "skiff"

    # Start the background process
    context.background_proc = subprocess.Popen(
        [str(skiff)] + shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


@behave.step("I quit the background process")
def step_impl(context):
    background_proc = getattr(context, "background_proc", None)
    if not background_proc:
        raise RuntimeError("No background process is running")

    if background_proc.poll() is not None:
        # Process already terminated
        stdout, stderr = background_proc.communicate()
        context.cmd_exitcode = background_proc.returncode
        context.cmd_stdout = stdout.decode()
        context.cmd_stderr = stderr.decode()
    else:
        # Terminate the process gracefully
        background_proc.terminate()
        try:
            stdout, stderr = background_proc.communicate(timeout=5)
            context.cmd_exitcode = background_proc.returncode
            context.cmd_stdout = stdout.decode()
            context.cmd_stderr = stderr.decode()
        except subprocess.TimeoutExpired:
            # Force kill if it doesn't terminate gracefully
            background_proc.kill()
            stdout, stderr = background_proc.communicate()
            context.cmd_exitcode = background_proc.returncode
            context.cmd_stdout = stdout.decode()
            context.cmd_stderr = stderr.decode()

    context.background_proc = None
    context.cmd_exitcode_checked = False


@behave.step('I wait for the background process to output "{expected_output}"')
def step_impl(context, expected_output: str) -> None:
    """Wait for the background process to output a specific string."""
    wait_for_background_output(context, expected_output, timeout=30)


@behave.step(
    'I wait for the background process to output "{expected_output}" within {timeout:d} seconds'
)
def step_impl(context, expected_output: str, timeout: int) -> None:
    """Wait for the background process to output a specific string with custom timeout."""
    wait_for_background_output(context, expected_output, timeout)


def wait_for_background_output(
    context, expected_output: str, timeout: int = 30
) -> None:
    """Wait for the background process to output a specific string."""
    background_proc = getattr(context, "background_proc", None)
    if not background_proc:
        raise RuntimeError("No background process is running")

    if background_proc.poll() is not None:
        raise RuntimeError("Background process has already terminated")

    # Replace {temp_dir} with the actual temporary directory
    if hasattr(context, "temp_dir"):
        expected_output = expected_output.replace("{temp_dir}", context.temp_dir)

    # Read output line by line until we find the expected output
    import select

    output_lines = []
    start_time = time.time()

    while time.time() - start_time < timeout:
        if background_proc.poll() is not None:
            # Process terminated
            stdout, stderr = background_proc.communicate()
            all_output = stdout.decode() + stderr.decode()
            raise RuntimeError(
                f"Background process terminated before expected output. Output:\n{all_output}"
            )

        # Check if there's data to read (non-blocking)
        ready, _, _ = select.select(
            [background_proc.stdout, background_proc.stderr], [], [], 0.1
        )

        for stream in ready:
            if stream == background_proc.stdout:
                line = stream.readline().decode().strip()
                if line:
                    output_lines.append(line)
                    if expected_output in line:
                        return  # Found the expected output
            elif stream == background_proc.stderr:
                line = stream.readline().decode().strip()
                if line:
                    output_lines.append(line)
                    if expected_output in line:
                        return  # Found the expected output

    # Timeout reached
    all_output = "\n".join(output_lines)
    raise RuntimeError(
        f"Timeout waiting for '{expected_output}' in background process output after {timeout}s. Captured output:\n{all_output}"
    )
