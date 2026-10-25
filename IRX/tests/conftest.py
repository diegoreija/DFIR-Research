def pytest_addoption(parser):
    parser.addoption(
        "--evtx-file",
        action="store",
        default=None,
        metavar="PATH",
        help="Run the real EVTX end-to-end integration test against PATH.",
    )
