import pytest


@pytest.fixture
def data_to_use():
    return None


def bench_example(benchmark, data_to_use):
    def function_to_measure(x):
        pass

    def setup():
        pass

    args = [data_to_use]
    kwargs = {}
    rounds = 1000

    benchmark.pedantic(
        function_to_measure,
        setup=setup,
        args=args,
        kwargs=kwargs,
        rounds=rounds,
    )
