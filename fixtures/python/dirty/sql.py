def load_charge(cursor, charge_id: str):
    return cursor.execute(f"SELECT * FROM charges WHERE id = '{charge_id}'")
