rule ExampleMarkerString {
    strings:
        $a = "RUSTINEL_TEST_MARKER" ascii wide
    condition:
        $a
}
