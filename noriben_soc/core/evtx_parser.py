from pathlib import Path
def parse_evtx(path: Path) -> list:
    try:
        import Evtx.Evtx as evtx
        with evtx.Evtx(str(path)) as log:
            return [{"xml": r.xml()} for r in log.records()]
    except Exception as e:
        return [{"error": str(e)}]