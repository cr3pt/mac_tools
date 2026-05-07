import tempfile
from noriben_soc.core.static_analysis import analyze_file


def test_analyze_text_file():
    # create a small text file and analyze
    with tempfile.NamedTemporaryFile('wb', delete=False) as tf:
        tf.write(b'Hello world\nThis is a test file.\nhttp://example.com\nMZ')
        path = tf.name
    res = analyze_file(path, report=False)
    assert 'filename' in res
    assert res['size'] > 0
    assert 'entropy' in res
    assert isinstance(res['strings'], list)
    assert 'yara_matches' in res
    assert 'iocs' in res
    assert 'sha256' in res
