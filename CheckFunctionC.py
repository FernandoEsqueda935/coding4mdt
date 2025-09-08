
cnt_f_open = 0
func_name = ''
case_name = ''
cases_in_funct = []

block_all = []
validate_all = []

with open ('OIDtable.c', 'r') as c_file:
    for cl in c_file:
        if ( not (cl.startswith('/')) and cnt_f_open == 0 and cl != '\n' and func_name == ''):
            if (cl.strip() == "BOOLEAN"):
                cl = next(c_file, None)
                func_name = cl.split(" ")[0].split("(")[0]
                continue
            if ( "static" in cl ):
                func_name = cl.split(" ")[2].split("(")[0]
                continue
            try:
                func_name = cl.split(" ")[1].split("(")[0]
            except:
                func_name = cl
        if ( '{' in cl ) : 
            cnt_f_open += 1
        if ( '}' in cl ) :
            cnt_f_open -= 1
            if ( cnt_f_open == 0 ):
                func_name = ''
                case_name = ''
                cases_in_funct = []
        if ( 'case' in cl and '//' in cl and ':' in cl ) :
            case_name = cl
            try:
                case_name = case_name.split(" ")[-1]
            except:
                case_name = cl
            cases_in_funct.append(case_name)
        if ( 'default' in cl ) :
            case_name = ''
        if ('if (eNtcipTableAccess == BLOCK_TABLE_DECODE)' in cl):
            if (case_name == ''):
                if (len(cases_in_funct) == 0):
                    block_all.append(func_name)
                else:
                    block_all.extend(cases_in_funct)
            else:
                block_all.append(case_name)
        if ('if (validate)' in cl or "if (bValidate)" in cl):
            if (case_name == ''):
                if (len(cases_in_funct) == 0):

                    validate_all.append(func_name)
                else:
                    validate_all.extend(cases_in_funct)
            else: 
                validate_all.append(case_name)

cnt = 0
print("BLOCK TABLE DECODE en:")
for b in block_all:
    cnt += 1
    print(cnt, b.strip())
cnt = 0
print("\nVALIDATE en:")
for v in validate_all:  
    cnt += 1
    print(cnt, v.strip())

both_all = set(block_all) & set(validate_all)
cnt = 0
print("\nBOTH en:")
for bo in both_all:
    cnt += 1
    print(cnt, bo.strip())
print("\nTotal BLOCK TABLE DECODE: ", len(block_all))
print("Total VALIDATE: ", len(validate_all))
print("Total BOTH: ", len(both_all))

