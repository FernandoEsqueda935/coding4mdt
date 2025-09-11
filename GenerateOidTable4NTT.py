from OIDTable import *
from Framework.ASN import *
import ast
import re


def type2NTTtype (typ):
  if (typ == 'OBJT_DISPLAY_STR' or typ == "OBJT_OCTET" or typ == "OBJT_PHYS_ADDR" or typ == "OBJT_OWNER_STR"):
    return "ASN_OCTET_STR"
  elif (typ.startswith("OBJT_INT") or typ.startswith("OBJT_SIGN")):
    return "ASN_INTEGER"
  elif (typ == "OBJT_OID"):
    return "ASN_OBJECT_ID"
  elif (typ == "OBJT_IP_ADDR"):
    return "ASN_IPADDRESS"
  elif (typ == "OBJT_COUNTER"):
    return "ASN_COUNTER"
  elif (typ == "OBJT_GAUGE"):
    return "ASN_GAUGE"
  elif (typ == "OBJT_TIME_TICKS"):
    return "ASN_TIMETICKS"

def formatOid (oid):
  ret = "'"
  ret = ret + oid[0].strip()
  for n, idx in zip(oid[1:], range(len(oid[1:]))):
    n = n.strip()
    ret = ret + "." + n
    if (n == '0' or idx == (len(oid[1:]) -1)):
      ret = ret + "'"
      break
  return ret

def formatDimension(dim):
  ret = "("
  for n in dim[:3]:
    n = n.strip()
    ret = ret + n + ','
  ret = ret + dim[3].strip() + ')'
  return ret

def generate_oid_table():
    oid_table_found = False
    cnt = 0
    line_splitted = ''
    line_len = 0

    current_oid_s = { "oid_id" : "", "oid_dim": "", "access": "", "range": "", "type": "", "oid_name": "", "priority" : "mandatory" }

    #print(OIDTable)

    oids_all = "new_oids = {"

    # oid_id = ""
    # dimensiones = []
    # acceso = ""
    # rangos = []
    # tipo = ""
    # nombre = ""

    with open("OIDTable.c", "r") as oid_table:
      for cl in oid_table:
          if (oid_table_found):
              if ("{-1, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, 0, 0, 0, 0, 0, NULL, " in cl):
                oid_table_found = False
              
              line_splitted = cl.strip().replace('{', '').replace('}', '').replace("| AF_BU", '').split(',')
              line_len = len(line_splitted)
              
              if not line_splitted[0].startswith("/") and line_len == 30:
                current_oid_s["oid_id"] = formatOid(line_splitted[1:17])
                current_oid_s["oid_dim"] = str(line_splitted[22])
                current_oid_s["access"] = str(line_splitted[23]).strip()
                current_oid_s["range"] = str(line_splitted[24]).strip()
                current_oid_s["type"] = type2NTTtype(line_splitted[25].strip())
                current_oid_s["oid_name"] = str(line_splitted[27]).strip()


                current_oid = formatOid(line_splitted[1:17])
                full_current_oid = current_oid + " : " + '[ ' +  current_oid_s["oid_id"] + "," + current_oid_s["oid_dim"] + ","+ "(" + current_oid_s["access"] + ", " + current_oid_s["range"] + ")" + "," + current_oid_s["type"] + "," + current_oid_s["oid_name"] + "," + '"mandatory"' + "],\n"
                try:
                  temp = OIDTable[current_oid.strip("'")]
                except: 
                  oids_all = oids_all + full_current_oid
                  oids_all = re.sub(r'/\*.*?\*/', '', oids_all)
                  print("Oid nuevo:", current_oid_s["oid_name"])

              if cnt > 1600:
                oids_all = oids_all + "}"
                print ("\n****///******///***** NEW OIDS ******///******///******\n")
                
                print(oids_all)
                # for (new_oid, new_value), (old_oid, old_value) in zip(new_oid_table.items(), OIDTable.items()):
                #    if (new_oid != old_oid):
                #      print("diff")
                #      #print(new_oid, old_oid)
                #      break
                break
              cnt += 1
          else:
              if ("TYPE_OIDTABLE OID[] = {" in cl):
                  print("Oid table found ")
                  oid_table_found = True
          

generate_oid_table()
