

def generate_oid_table():
    oid_table_found = False
    cnt = 0
    line_splitted = ''
    line_len = 0

    with open("OIDTable.c", "r") as oid_table:
      for cl in oid_table:
          if (oid_table_found):
              line_splitted = cl.strip("{}").split(',')
              line_len = len(line_splitted)
              print(line_splitted)
              if ("{-1, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, 0, 0, 0, 0, 0, NULL, " in cl):
                oid_table_found = False
              if cnt > 3:
                break
              cnt += 1
          else:
              if ("TYPE_OIDTABLE OID[] = {" in cl):
                  print("Oid table found ")
                  oid_table_found = True
          

generate_oid_table()
