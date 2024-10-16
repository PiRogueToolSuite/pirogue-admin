from functools import reduce


def json_chain(json_obj, keys):
    """
    Traverse json_obj with keys dotted chain expression if exists.
    Returns None otherwise.
    Assuming json_obj is {a: {b: {c: bar}}
    with keys: 'a.b.c' returns bar
    with keys: 'a.foo.c' return None
    """
    try:
        return reduce(
            lambda x, y: x[int(y)] if y.isdigit() else x.get(y, None),
            keys.split('.'), json_obj)
    except AttributeError:
        return None
    except KeyError:
        return None
    except IndexError:
        return None

