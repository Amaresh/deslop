def warm(loader):
    try:
        loader.refresh()
    except Exception:
        pass
