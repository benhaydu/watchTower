import enrichment
from enrichment import open_reader, lookup_ip

EMPTY = {"country": None, "asn": None, "org": None}


class FakeReader:
    """Stands in for a maxminddb Reader: same .get(ip) behaviour, no file needed."""

    def __init__(self, records):
        self.records = records

    def get(self, ip):
        if not isinstance(ip, str):
            raise TypeError("argument must be a string")
        if ip == "not-an-ip":
            raise ValueError(f"{ip!r} does not appear to be an IPv4 or IPv6 address")
        return self.records.get(ip)


COUNTRY = FakeReader({
    "8.8.8.8": {"country": {"iso_code": "US"}},
    "9.9.9.9": {"continent": {"code": "EU"}},            # no "country" key
    "7.7.7.7": {"country": {"names": {"en": "X"}}},      # country but no iso_code
})
ASN = FakeReader({
    "8.8.8.8": {"autonomous_system_number": 15169,
                "autonomous_system_organization": "Google LLC"},
    "9.9.9.9": {"autonomous_system_number": 19281},      # number but no org
})


# ---- lookup_ip ----
def test_none_ip_gives_all_none():
    assert lookup_ip(None, COUNTRY, ASN) == EMPTY

def test_full_hit():
    assert lookup_ip("8.8.8.8", COUNTRY, ASN) == {
        "country": "US", "asn": 15169, "org": "Google LLC"}


def test_unknown_or_private_ip_gives_all_none():
    assert lookup_ip("10.0.0.1", COUNTRY, ASN) == EMPTY


def test_malformed_ip_gives_all_none_not_exception():
    assert lookup_ip("not-an-ip", COUNTRY, ASN) == EMPTY


def test_both_readers_none():
    assert lookup_ip("8.8.8.8", None, None) == EMPTY


def test_country_reader_only():
    assert lookup_ip("8.8.8.8", COUNTRY, None) == {
        "country": "US", "asn": None, "org": None}


def test_asn_reader_only():
    assert lookup_ip("8.8.8.8", None, ASN) == {
        "country": None, "asn": 15169, "org": "Google LLC"}


def test_record_without_country_key_keeps_asn():
    assert lookup_ip("9.9.9.9", COUNTRY, ASN) == {
        "country": None, "asn": 19281, "org": None}


def test_country_without_iso_code():
    assert lookup_ip("7.7.7.7", COUNTRY, None)["country"] is None


def test_always_returns_a_new_dict():
    a = lookup_ip("10.0.0.1", None, None)
    a["country"] = "ZZ"
    assert lookup_ip("10.0.0.1", None, None) == EMPTY


# ---- open_reader ----

def test_unset_variable(monkeypatch, capsys):
    monkeypatch.delenv("WT_TEST_DB", raising=False)
    assert open_reader("WT_TEST_DB") is None
    assert "WT_TEST_DB" in capsys.readouterr().out


def test_empty_variable(monkeypatch, capsys):
    monkeypatch.setenv("WT_TEST_DB", "")
    assert open_reader("WT_TEST_DB") is None
    assert "WT_TEST_DB" in capsys.readouterr().out


def test_missing_file(monkeypatch, tmp_path, capsys):
    path = str(tmp_path / "nope.mmdb")
    monkeypatch.setenv("WT_TEST_DB", path)
    assert open_reader("WT_TEST_DB") is None
    out = capsys.readouterr().out
    assert "WT_TEST_DB" in out and path in out


def test_invalid_database_file(monkeypatch, tmp_path, capsys):
    bad = tmp_path / "bad.mmdb"
    bad.write_text("this is not a maxmind database")
    monkeypatch.setenv("WT_TEST_DB", str(bad))
    assert open_reader("WT_TEST_DB") is None
    out = capsys.readouterr().out
    assert "WT_TEST_DB" in out and str(bad) in out


def test_valid_path_is_passed_to_maxminddb(monkeypatch):
    seen = []
    monkeypatch.setattr(enrichment.maxminddb, "open_database",
                        lambda p: seen.append(p) or "READER")
    monkeypatch.setenv("WT_TEST_DB", "/some/full/path.mmdb")
    assert open_reader("WT_TEST_DB") == "READER"
    assert seen == ["/some/full/path.mmdb"]