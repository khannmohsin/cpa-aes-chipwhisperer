"""Import-safety and CLI tests for capture.py (no hardware SDK needed)."""


def test_capture_imports_without_hardware(capsys):
    """Regression: the old module called print_versions() at import time and
    sys.exit(1)-ed when chipwhisperer was missing, so `from capture import
    connect` blew up on any machine without the SDK."""
    import capture

    out = capsys.readouterr().out
    assert "Step 0" not in out            # nothing printed at import time
    assert hasattr(capture, "connect")
    assert hasattr(capture, "flash_firmware")
    assert hasattr(capture, "capture_pairs")
    assert hasattr(capture, "record_traces")


def test_attack_imports_without_plot_deps(capsys):
    import attack

    assert attack.sbox[0xFF] == 0x16
    assert capsys.readouterr().out == ""


def test_parse_args_defaults():
    import capture

    args = capture.parse_args([])
    assert args.traces == 200
    assert args.samples == 5000
    assert args.gain == 25
    assert args.firmware.endswith("simpleserial-aes-CWLITEXMEGA.hex")


def test_parse_args_overrides():
    import capture

    args = capture.parse_args(["--traces", "50", "--samples", "1000", "--gain", "30"])
    assert args.traces == 50
    assert args.samples == 1000
    assert args.gain == 30


def test_record_traces_uses_module_settings():
    """The capture loop reads NUM_TRACES from the module, matching the old
    'settings at the top of capture.py' behaviour."""
    import capture

    assert capture.NUM_TRACES == 200
    assert capture.NUM_SAMPLES == 5000
    assert capture.GAIN == 25