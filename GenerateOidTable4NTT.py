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
  elif (typ == "OBJT_OPAQUE"):
    return typ

def formatOid (oid):
  ret = "'"
  ret = ret + oid[0].strip()
  for n, idx in zip(oid[1:], range(len(oid[1:]))):
    n = n.strip()
    ret = ret + "." + n
    if (n == '0' or idx == (len(oid[1:]) -1)):
      if (n != '0'):
        ret = ret + '.' + "0'" 
      else:
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

def nextOidOnTable(table, new_table):
  cnt = 0
  for cl in table:
    if (len(cl.split(":")) == 2):
      return cl, cnt
    else:
      cnt -= 1
      new_table.append(cl)

def generate_oid_table():
    oid_table_found = False
    cnt = 0
    line_splitted = ''
    line_len = 0

    current_oid_s = { "oid_id" : "", "oid_dim": "", "access": "", "range": "", "type": "", "oid_name": "", "priority" : "mandatory" }

    oids_all = "new_oids = { \n"

    new_file = open("newOIDTable.py", "w")
    oidTable_file = open("OIDTable.py", "r")
    new_table = open("newTable.py","w")
    
    for line in oidTable_file:
      new_file.write(line)
      new_table.write(line)
      if ("OIDTable = { " in line):
        break
    
    line_py = ""
    new_oid_table = ""
    full_updated_oid_table = []
    new_oid_f = False
    cnt = 0

    with open("OIDTable.c", "r") as oid_table:
      for cl in oid_table:
          if (oid_table_found):
              line_splitted = cl.strip().replace('{', '').replace('}', '').replace("| AF_BU", '').split(',')
              line_len = len(line_splitted)


              if ("{-1, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, 0, 0, 0, 0, 0, NULL, " in cl):
                full_updated_oid_table.append("\n}\n")
                new_oid_table = new_oid_table + "\n}\n"
                new_table.write(new_oid_table)
                break
              
              elif not line_splitted[0].startswith("/") and line_len == 30:
                current_oid_s["oid_id"] = formatOid(line_splitted[1:17])
                current_oid_s["oid_dim"] = formatDimension(line_splitted[17:22])
                current_oid_s["access"] = str(line_splitted[22])
                current_oid_s["range_min"] = str(line_splitted[23]).strip()
                current_oid_s["range_max"] = str(line_splitted[24]).strip()
                current_oid_s["type"] = type2NTTtype(line_splitted[25].strip())
                current_oid_s["oid_name"] = str(line_splitted[27]).strip()

                full_current_oid = "\t\t" + current_oid_s["oid_id"] + " : " + '[ ' + current_oid_s["oid_dim"]+ "," + current_oid_s["access"] + ","+ "(" + current_oid_s["range_min"] + ", " + current_oid_s["range_max"] + ")" + "," + current_oid_s["type"] + "," + current_oid_s["oid_name"] + "," + '"mandatory"' + "],\n"
                if new_oid_f == False:
                  line_py, cnt = nextOidOnTable(oidTable_file, full_updated_oid_table)

                try:
                  temp = OIDTable[current_oid_s["oid_id"].strip("'")]

                  if (temp[4].strip(" ") == current_oid_s["oid_name"].strip('"')):
                    full_updated_oid_table.append(line_py)
                    print("finished", cl, "\n", line_py)
                    new_oid_f = False
                  else:
                    print("There's a OID with different names", temp[4])
                    new_oid_f = False
                  

                except: 
                  
                  try: 
                    temp = OIDTable[current_oid_s["oid_name"].strip('"')]
                    print("There's a OID name with different ID's")
                    new_oid_f = False
                  except:
                    if (cnt == 0):
                      full_updated_oid_table.append(re.sub(r'/\*.*?\*/', '', full_current_oid))
                    else: 
                      full_updated_oid_table.insert( cnt , re.sub(r'/\*.*?\*/', '', full_current_oid))
                    new_oid_f = True

                    new_oid_table = new_oid_table + re.sub(r'/\*.*?\*/', '', full_current_oid)

                    print("New Oid added:", current_oid_s["oid_name"])
          else:
              if ("TYPE_OIDTABLE OID[] = {" in cl):
                  print("Oid table found ")
                  oid_table_found = True
    for cl in full_updated_oid_table:
      new_file.write(cl)
    
    new_file.close()
          
generate_oid_table()
