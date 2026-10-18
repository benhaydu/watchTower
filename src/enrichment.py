import maxminddb
import os

def open_reader(env_var):
   x_var = os.getenv(env_var)

   if(not x_var):
      print(f"Empty variable: {env_var}")
      return None
  
   try:
        return maxminddb.open_database(x_var)
   except FileNotFoundError:
        print(f"{env_var}: Error file does not exist at: {x_var}")
        return None
   except maxminddb.InvalidDatabaseError as e:
        print(f"{env_var}: Invalid Database error: {e} at file path {x_var}")
        return None
   except OSError as e:
        print(f"{env_var}: System error caught: {e} at path{x_var}")
        return None


def lookup_ip(ip, country_reader, asn_reader):
    result = {"country": None, "asn": None, "org": None}
    if country_reader is not None:
        try:
            record = country_reader.get(ip)
        except ValueError:                   
            return result
        else:
            if record:                # None for private/unknown IPs
                result["country"] = (record.get("country") or {}).get("iso_code")

    if asn_reader is not None:
        try:
            record = asn_reader.get(ip)
        except ValueError:
            return result
        else:
            if record:              
                result["asn"] = record.get("autonomous_system_number")
                result["org"] = record.get("autonomous_system_organization")                         
    return result