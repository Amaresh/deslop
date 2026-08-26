def display_name(row):
    try:
        return row['label']
    except KeyError:
        pass
    return 'untitled'
