#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/library/snmp_transport.h>

#include "../../includes/common/blockDefines/blockEnums.h"
#include "../../includes/common/nonVolatile/nonVolatileDefines.h"
#include "../../includes/lib/shmem.h"
#include "../../traffic/trafficDefines.h"

#include "OIDTableFmt.h"
#include "blocks/berUtilsMA.h"
#include "blocks/blocksMA.h"

#include "oid.h"

// RFC1213 handlers includes
#include "RFC_1213/interfaces/interfaces.h"
#include "RFC_1213/ip/ip.h"
#include "RFC_1213/snmp/snmpStat.h"
#include "RFC_1213/system/system.h"
#include "RFC_1213/tcp/tcp.h"
#include "RFC_1213/udp/udp.h"

// McCain handlers includes
#include "mcCainOmni/mcAtcCommunication/mcAtcCommunication.h"
#include "mcCainOmni/mcAtcControllerLog/mcAtcControllerLog.h"
#include "mcCainOmni/mcAtcCoord/mcAtcCoord.h"
#include "mcCainOmni/mcAtcCycleMOELog/mcAtcCycleMOELog.h"
#include "mcCainOmni/mcAtcDetector/mcAtcDetector.h"
#include "mcCainOmni/mcAtcDetectorVOSLog/mcAtcDetectorVOSLog.h"
#include "mcCainOmni/mcAtcIoMapping/mcAtcAuxSwitch/mcAtcAuxSwitch.h"
#include "mcCainOmni/mcAtcIoMapping/mcAtcFioIoMapping/mcAtcFioIoMapping.h"
#include "mcCainOmni/mcAtcIoMapping/mcAtcIoLogic/mcAtcIoLogic.h"
#include "mcCainOmni/mcAtcIoMapping/mcAtcItsDevices/mcAtcItsDevices.h"
#include "mcCainOmni/mcAtcIoMapping/mcAtcItsIoMapping/mcAtcItsIoMapping.h"
#include "mcCainOmni/mcAtcIoMapping/mcAtcNemaIoMapping/mcAtcNemaIoMapping.h"
#include "mcCainOmni/mcAtcIoMapping/mcAtcTs2IoMapping/mcAtcTs2IoMapping.h"
#include "mcCainOmni/mcAtcMenuPermissions/mcAtcMenuPermissions.h"
#include "mcCainOmni/mcAtcOverlap/mcAtcOverlap.h"
#include "mcCainOmni/mcAtcPedOverlap/mcAtcPedOverlap.h"
#include "mcCainOmni/mcAtcPedestrianDetector/mcAtcPedestrianDetector.h"
#include "mcCainOmni/mcAtcPhase/mcAtcPhase.h"
#include "mcCainOmni/mcAtcPreempt/mcAtcPreempt.h"
#include "mcCainOmni/mcAtcPriority/mcAtcPriority.h"
#include "mcCainOmni/mcAtcSpeedTrap/mcAtcSpeedTrap.h"
#include "mcCainOmni/mcAtcTimeSync/mcAtcTimeSync.h"
#include "mcCainOmni/mcAtcTimebase/mcAtcTimebase.h"
#include "mcCainOmni/mcAtcUnit/mcAtcUnit.h"
#include "mcCainOmni/mcAtcCic/mcAtcCic.h"
#include "mcCainOmni/mcAtcBlocksDefinitions/mcAtcBlocksDefinitions.h"
#include "mcCainOmni/mcAtcBoston/mcAtcBoston.h"
#include "mcCainOmni/mcAtcBotStatus/mcAtcBotStatus.h"
#include "mcCainOmni/mcAtcConnectedVehicle/mcAtcSpat/mcAtcSpat.h"
#include "mcCainOmni/mcAtcDayOfWeek/mcAtcDayOfWeek.h"
#include "mcCainOmni/mcAtcHiResLog/mcAtcHiResLog.h"
#include "mcCainOmni/mcAtcP2p/mcAtcP2p.h"
#include "mcCainOmni/mcAtcSecurity/mcAtcSecUsers/mcAtcSecUsers.h"

// Standard (NTCIP) handlers includes
#include "NTCIP/NTCIP_1103/dynObjMgmt/dynObjMgmt.h"
#include "NTCIP/NTCIP_1103/globalReport/globalReport.h"
#include "NTCIP/NTCIP_1103/profilesSTMP/profilesSTMP.h"
#include "NTCIP/NTCIP_1103/security/security.h"
#include "NTCIP/NTCIP_1103/stmp/stmpStat.h"
#include "NTCIP/NTCIP_1201/globalConfiguration/globalConfiguration.h"
#include "NTCIP/NTCIP_1201/globalDBManagement/globalDBManagement.h"
#include "NTCIP/NTCIP_1201/globalTimeManagement/globalTimeManagement.h"
#include "NTCIP/NTCIP_1202/ascBlock/ascBlock.h"
#include "NTCIP/NTCIP_1202/channel/channel.h"
#include "NTCIP/NTCIP_1202/coord/coord.h"
#include "NTCIP/NTCIP_1202/detector/detector.h"
#include "NTCIP/NTCIP_1202/hdlcGroupAddress/hdlcGroupAddress.h"
#include "NTCIP/NTCIP_1202/logicalNames/logicalNames.h"
#include "NTCIP/NTCIP_1202/overlap/overlap.h"
#include "NTCIP/NTCIP_1202/phase/phase.h"
#include "NTCIP/NTCIP_1202/preempt/preempt.h"
#include "NTCIP/NTCIP_1202/ring/ring.h"
#include "NTCIP/NTCIP_1202/timebaseAsc/timebaseAsc.h"
#include "NTCIP/NTCIP_1202/ts2port1/ts2port1.h"
#include "NTCIP/NTCIP_1202/unit/unit.h"

// Ramp Meter includes
// #include "NTCIP/NTCIP_1207/mcRmcIoMapping/mcRmcAuxSwitch/mcRmcAuxSwitch.h"
// #include "NTCIP/NTCIP_1207/mcRmcIoMapping/mcRmcIoLogic/mcRmcIoLogic.h"
#include "mcCainOmni/mcRmcAuxiliaryOutputs/mcRmcAuxiliaryOutputs.h"
#include "mcCainOmni/mcRmcBlocksDefinitions/mcRmcBlocksDefinitions.h"
#include "mcCainOmni/mcRmcIoMapping/mcRmcFioIoMapping/mcRmcFioIoMapping.h"
#include "mcCainOmni/mcRmcIoMapping/mcRmcItsDevices/mcRmcItsDevices.h"
#include "mcCainOmni/mcRmcIoMapping/mcRmcItsIoMapping/mcRmcItsIoMapping.h"
#include "mcCainOmni/mcRmcIoMapping/mcRmcNemaIoMapping/mcRmcNemaIoMapping.h"
#include "mcCainOmni/mcRmcIoMapping/mcRmcTs2IoMapping/mcRmcTs2IoMapping.h"
#include "mcCainOmni/mcRmcMeter/mcRmcMeter.h"
#include "mcCainOmni/mcRmcQueue/mcRmcQueue.h"

#include "NTCIP/NTCIP_1207/meteringPlan/meteringPlan.h"
#include "NTCIP/NTCIP_1207/rampMeter.h"
#include "NTCIP/NTCIP_1207/rmcInOutput/rmcInOutput.h"
#include "NTCIP/NTCIP_1207/rmcML/rmcML.h"
#include "NTCIP/NTCIP_1207/rmcMeter/rmcDependGroup/rmcDependGroup.h"
#include "NTCIP/NTCIP_1207/rmcMeter/rmcMeter.h"
#include "NTCIP/NTCIP_1207/rmcMeter/rmcMeterMain/rmcMeterMain.h"
#include "NTCIP/NTCIP_1207/rmcMeter/rmcPassage/rmcPassage.h"
#include "NTCIP/NTCIP_1207/rmcMeter/rmcQueue/rmcQueue.h"
#include "NTCIP/NTCIP_1207/rmcTimebase/rmcTimebase.h"

// definitions of maximum sub nodes
#define MAX_MCCAIN_MIB_SUBNODES 30
#define MAX_MCCAIN_RAMPMETER_MIB_SUBNODES 30

typedef enum {
  RFC_1213,
  MCCAIN,
  MCCAIN_RM,
  NTCIP_1103,
  NTCIP_1201,
  NTCIP_1103a,
  NTCIP_1202,
  NTCIP_1207,
  NTCIP_1201a,
  NTCIP_1103b,
  MAX_MIB_NODES
} ENUM_TABLE_MIB_GROUPS;

char *Labels[MAX_MIB_NODES] = {
    "RFC_1213",
    "MCCAIN",
    "MCCAIN_RM",
    "NTCIP_1103",
    "NTCIP_1201",
    "NTCIP_1103a",
    "NTCIP_1202",
    "NTCIP_1207",
    "NTCIP_1201a",
    "NTCIP_1103b",
};

INT8U u8OMNItoASNtype[] = {
    0x02, // OBJT_INT1,        //!< NTCIP identifier = 0x02
    0x02, // OBJT_INT2,        //!< NTCIP identifier = 0x02
    0x02, // OBJT_INT4,        //!< NTCIP identifier = 0x02
    0x02, // OBJT_SIGN_INT1,   //!< NTCIP identifier = 0x02
    0x02, // OBJT_SIGN_INT2,   //!< NTCIP identifier = 0x02
    0x02, // OBJT_SIGN_INT4,   //!< NTCIP identifier = 0x02
    0x02, // OBJT_INT_UNRES,   //!< NTCIP identifier = 0x02
    0x04, // OBJT_OCTET,       //!< NTCIP identifier = 0x04
    0x04, // OBJT_DISPLAY_STR, //!< NTCIP identifier = 0x04
    0x04, // OBJT_PHYS_ADDR,   //!< NTCIP identifier = 0x04
    0x04, // OBJT_OWNER_STR,   //!< NTCIP identifier = 0x04
    0x05, // OBJT_NULL,        //!< NTCIP identifier = 0x05
    0x06, // OBJT_OID,         //!< NTCIP identifier = 0x06
    0x40, // OBJT_IP_ADDR,     //!< NTCIP identifier = 0x40
    0x41, // OBJT_COUNTER,     //!< NTCIP identifier = 0x41
    0x42, // OBJT_GAUGE,       //!< NTCIP identifier = 0x42
    0x43, // OBJT_TIME_TICKS,  //!< NTCIP identifier = 0x43
    0x44, // OBJT_OPAQUE       //!< NTCIP identifier = 0x44
};

INT16U au16RowMibNodeStart[MAX_MIB_NODES] = {0};
INT16U au16RowMcCainMibSubNodeStart[MAX_MCCAIN_MIB_SUBNODES] = {0};
INT16U u16NumberOfOIDS = 0;

/*************************************************************************************************/
/*  Name       : vFistRowMibGroups                                                               */
/*                                                                                               */
/*  Description: Find the row of OID table assigned for each Label type group first occurrence   */
/*               and stored in au8RowMibGroupStart array                                         */
/*                                                                                               */
/*************************************************************************************************/
void vFistRowMibGroups(void)
{
  INT16U u16Row = 0;
  INT8U u8LastLabel = INT8U_MAX;

  do {

    if (OID[u16Row].oidBaseIdx != u8LastLabel) {
      u8LastLabel++;
      if (u8LastLabel == MAX_MIB_NODES) {
        break;
      }
      au16RowMibNodeStart[u8LastLabel] = u16Row; // store row number as starting row of group
      // printf("Label_Num: %d Label: [%s] --> %d Name: %s\n", u8LastLabel, Labels[u8LastLabel], u16Row, OID[u16Row].pcOidName);
      //  vMcSysLog(LOG_INFO, "Label_Num: %d Label: [%s] --> %d Name: %s\n", u8LastLabel, Labels[u8LastLabel], u16Row, OID[u16Row].pcOidName);
    }

    u16Row++;
  } while (OID[u16Row].oidBaseIdx != -1 && u16Row < u16NumberOfOIDS);
}

/*************************************************************************************************/
/*  Name       : vFistRowMcAtcMibSubGroups                                                       */
/*                                                                                               */
/*  Description: Find the row of OID table assigned for each McAtc sub groups first occurrence   */
/*               and stored in au8RowMcCainMibSubGroupStart array                                */
/*                                                                                               */
/*        Notes:                                                                                 */
/*                - The discriminator element of the OID is the 10th                             */
/*                - The maximum value of the discriminator element of the OID is 28              */
/*                                                                                               */
/*************************************************************************************************/
void vFistRowMcAtcMibSubGroups(void)
{
  INT16U u16Row = 0;
  INT8U u8LastLabel = 1; // discriminator OID element value

  u16Row = au16RowMibNodeStart[MCCAIN]; // starting search in McCain group

  do {

    if (OID[u16Row].oidNum[10] != u8LastLabel) {
      u8LastLabel = OID[u16Row].oidNum[10];
      au16RowMcCainMibSubNodeStart[OID[u16Row].oidNum[10]] = u16Row; // store row number as starting row of McCain sub group
      // printf("McCain: %d   %d Name: %s\n", u8LastLabel, u16Row, OID[u16Row].pcOidName);
    }

    u16Row++;
  } while (OID[u16Row].oidNum[10] < 30 && u16Row < au16RowMibNodeStart[MCCAIN_RM]); // NTCIP_1103 is next to MCCAIN group
}

/*************************************************************************************************/
/*  Name       : bFindRowStart                                                                   */
/*                                                                                               */
/*  Description: Find a value used to be used as a starting index for the search an certain      */
/*               OID in OID table.                                                               */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN bFindRowStart(netsnmp_request_info *request, INT16U *u16Row)
{
  oid *reqOid = request->requestvb->name;

  if (reqOid[4] == 2) { // check for RFC_1213
    *u16Row = au16RowMibNodeStart[RFC_1213];
    return TRUE;
  } else if (reqOid[4] == 4) {
    if (reqOid[5] == 1) {
      if (reqOid[6] == 1206) {                    // Check for NEMA     1206
        if (reqOid[7] == 3 && reqOid[8] == 21) {  // check for MCCAIN  1206.3.21
          if (reqOid[9] == 2 || reqOid[9] == 3) { // check for McCain or McCain Ramp
            // MCCAIN 1206.3.21.2 to 29
            *u16Row = au16RowMcCainMibSubNodeStart[reqOid[10]]; // get start row number according to McCain sub group
            return TRUE;
          } else if (reqOid[9] == 3) { // McCain Ramp
            // MCCAIN_RM 1206.3.21.3 to ..
            *u16Row = au16RowMibNodeStart[MCCAIN_RM]; // get start row number according to McCain Ramp
            return TRUE;
          }
        } else if (reqOid[7] == 4) {
          if (reqOid[8] == 1) {
            if (reqOid[9] == 1) {
              *u16Row = au16RowMibNodeStart[NTCIP_1103];
              return TRUE;
            } else if (reqOid[9] == 2 && reqOid[10] == 2) {
              *u16Row = au16RowMibNodeStart[NTCIP_1103];
              return TRUE;
            } else if (reqOid[9] == 2 && reqOid[10] == 3) {
              *u16Row = au16RowMibNodeStart[NTCIP_1201];
              return TRUE;
            } else if (reqOid[9] == 3) {
              *u16Row = au16RowMibNodeStart[NTCIP_1103a];
              return TRUE;
            } else {
              return FALSE;
            }
          } else if (reqOid[8] == 2) {
            if (reqOid[9] == 1) {
              *u16Row = au16RowMibNodeStart[NTCIP_1202];
              return TRUE;
            } else if (reqOid[9] == 2) {
              *u16Row = au16RowMibNodeStart[NTCIP_1207];
              return TRUE;
            } else if (reqOid[9] == 6) {
              if (reqOid[10] >= 4) {
                *u16Row = au16RowMibNodeStart[NTCIP_1103a];
                return TRUE;
              }
              *u16Row = au16RowMibNodeStart[NTCIP_1201a];
              return TRUE;
            }
          }
        }
      }
    }
  }

  return FALSE; // the OID does not exist in the OID table
}

void vSetUpOIDTableConstants()
{
  // get the Max Qty of OID
  vGetOIDTableMax();

  // to improve the searching OID in OID Table
  vFistRowMibGroups();
  vFistRowMcAtcMibSubGroups();

  // Init blocks (standard, McCain and ramp meter blocks)
  vInitAscBlocks();
}

//==================================================================================================
//==================================================================================================
//                                  NTCIP object OID's
//==================================================================================================
//==================================================================================================

/* Generic OID handlers */
int hdlr_actionMax(netsnmp_request_info *requests, const TYPE_OIDTABLE *this);
int hdlr_mcAtcGenericDeprecatedObject(netsnmp_request_info *requests, const TYPE_OIDTABLE *this);

/* Local functions*/
INT16U u16getNextOID(INT16U u16Row, oid *nxtOID, INT8U *nxtOIDLen);
INT16U u16getNextScalarOID(INT16U u16Row, oid *nxtOID, INT8U *nxtOIDLen);
INT16U u16getNextRowFirstIndexTableOID(INT16U u16Row, oid *nxtOID, INT8U *nxtOIDLen);
INT16U u16getNextRowIndexTableOID(INT16U u16Row, oid *nxtOID, INT8U *nxtOIDLen);

// ---- System group RFC 1213 ---------
INT8U sysDescr[SIZE_SYSDESCR + 2];
INT8U sysObjectID[50] = {"1.3.6.1.4.1.1206.3.21.2"}; // this IOD is constant
INT8U sysServices[27] = {0};

TYPE_OIDTABLE OID[] = {

    // System - RFC 1213
    {RFC_1213, {1, 3, 6, 1, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, SIZE_SYSDESCR, OBJT_DISPLAY_STR, &hdlr_sysDescr, "sysDescr", NULL}, 
    {RFC_1213, {1, 3, 6, 1, 2, 1, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 50, OBJT_OID, &hdlr_sysObjectID, "sysObjectID", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_TIME_TICKS, &hdlr_sysUpTime, "sysUpTime", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, SIZE_SYSCONTACT, OBJT_DISPLAY_STR, &hdlr_sysContact, "sysContact", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 1, 5, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, SIZE_SYSNAME, OBJT_DISPLAY_STR, &hdlr_sysName, "sysName", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 1, 6, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, SIZE_SYSLOCATION, OBJT_DISPLAY_STR, &hdlr_sysLocation, "sysLocation", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 127, OBJT_INT1, &hdlr_sysServices, "sysServices", NULL},

    // Interface - RFC 1213
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2, OBJT_INT4, &hdlr_actionMax, "ifNumber", NULL},

    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_ifTable, "ifIndex", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, SIZE_IFDESCR, OBJT_DISPLAY_STR, &hdlr_ifTable, "ifDescr", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 3, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_ifTable, "ifType", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 4, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_ifTable, "ifMtu", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 5, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_ifTable, "ifSpeed", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_PHYS_ADDR, &hdlr_ifTable, "ifPhysAddress", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RW, 1, 3, OBJT_INT1, &hdlr_ifTable, "ifAdminStatus", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_ifTable, "ifOperStatus", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 9, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_TIME_TICKS, &hdlr_ifTable, "ifLastChange", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ifTable, "ifInOctets", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 11, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ifTable, "ifInUcastPkts", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 12, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ifTable, "ifInNUcastPkts", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 13, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ifTable, "ifInDiscards", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 14, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ifTable, "ifInErrors", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 15, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ifTable, "ifInUnknownProtos", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 16, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ifTable, "ifOutOctets", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 17, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ifTable, "ifOutUcastPkts", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 18, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ifTable, "ifOutNUcastPkts", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 19, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ifTable, "ifOutDiscards", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 20, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ifTable, "ifOutErrors", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 21, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_ifTable, "ifOutQLen", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 2, 2, 1, 22, 0, 0, 0, 0, 0, 0}, {NUM_IFS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 50, OBJT_OID, &hdlr_ifTable, "ifSpecific", NULL},

    // IP  -  RFC 1213
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 1, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 1, 2, OBJT_INT1, &hdlr_ip_Stat, "ipForwarding", &tIpForward},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 2, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_INT4, &hdlr_ip_Stat, "ipDefaultTTL", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 3, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipInReceives", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipInHdrErrors", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipInAddrErrors", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 6, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipForwDatagrams", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 7, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipInUnknownProtos", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipInDiscards", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 9, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipInDelivers", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 10, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipOutRequests", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 11, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipOutDiscards", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 12, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipOutNoRoutes", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 13, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_ip_Stat, "ipReasmTimeout", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 14, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipReasmReqds", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 15, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipReasmOKs", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipReasmFails", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 17, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipFragOKs", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 18, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipFragFails", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 19, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipFragCreates", NULL},

    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 0, 0, 0, 0, 0, 0}, {NUM_IPADDRS, 0, 0, 0}, NO_FILE, ACCESS_RD, 4, 4, OBJT_IP_ADDR, &hdlr_ipAddrTable, "ipAdEntAddr", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 20, 1, 2, 0, 0, 0, 0, 0, 0}, {NUM_IPADDRS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_ipAddrTable, "ipAdEntIfIndex", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 20, 1, 3, 0, 0, 0, 0, 0, 0}, {NUM_IPADDRS, 0, 0, 0}, NO_FILE, ACCESS_RD, 4, 4, OBJT_IP_ADDR, &hdlr_ipAddrTable, "ipAdEntNetMask", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 20, 1, 4, 0, 0, 0, 0, 0, 0}, {NUM_IPADDRS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_ipAddrTable, "ipAdEntBcastAddr", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 20, 1, 5, 0, 0, 0, 0, 0, 0}, {NUM_IPADDRS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_ipAddrTable, "ipAdEntReasmMaxSize", NULL},

    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 1, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RW, 4, 4, OBJT_IP_ADDR, &hdlr_ipRouteTable, "ipRouteDest", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 2, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_ipRouteTable, "ipRouteIfIndex", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 3, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_INT4, &hdlr_ipRouteTable, "ipRouteMetric1", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 4, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_INT4, &hdlr_ipRouteTable, "ipRouteMetric2", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 5, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_INT4, &hdlr_ipRouteTable, "ipRouteMetric3", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 6, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_INT4, &hdlr_ipRouteTable, "ipRouteMetric4", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 7, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RW, 4, 4, OBJT_IP_ADDR, &hdlr_ipRouteTable, "ipRouteNextHop", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 8, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RW, 1, 4, OBJT_INT1, &hdlr_ipRouteTable, "ipRouteType", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 9, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_ipRouteTable, "ipRouteProto", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 10, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_INT4, &hdlr_ipRouteTable, "ipRouteAge", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 11, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RW, 4, 4, OBJT_IP_ADDR, &hdlr_ipRouteTable, "ipRouteMask", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 12, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_INT4, &hdlr_ipRouteTable, "ipRouteMetric5", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 21, 1, 13, 0, 0, 0, 0, 0, 0}, {NUM_IPROUTES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 50, OBJT_OID, &hdlr_ipRouteTable, "ipRouteInfo", NULL},

    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 22, 1, 1, 0, 0, 0, 0, 0, 0}, {NUM_IPNETTOMEDIAS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_INT4, &hdlr_ipNetToMediaTable, "ipNetToMediaIfIndex", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 22, 1, 2, 0, 0, 0, 0, 0, 0}, {NUM_IPNETTOMEDIAS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_PHYS_ADDR, &hdlr_ipNetToMediaTable, "ipNetToMediaPhysAddress", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 22, 1, 3, 0, 0, 0, 0, 0, 0}, {NUM_IPNETTOMEDIAS, 0, 0, 0}, NO_FILE, ACCESS_RW, 4, 4, OBJT_IP_ADDR, &hdlr_ipNetToMediaTable, "ipNetToMediaNetAddress", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 22, 1, 4, 0, 0, 0, 0, 0, 0}, {NUM_IPNETTOMEDIAS, 0, 0, 0}, NO_FILE, ACCESS_RW, 1, 4, OBJT_INT1, &hdlr_ipNetToMediaTable, "ipNetToMediaType", &tIpToMediaType},

    {RFC_1213, {1, 3, 6, 1, 2, 1, 4, 23, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_ip_Stat, "ipRoutingDiscards", NULL},

    // TCP  - RFC 1213
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 1, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 4, OBJT_INT1, &hdlr_tcp_Stat, "tcpRtoAlgorithm", &tTcpAlgorithm},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 2, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_tcp_Stat, "tcpRtoMin", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 3, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_tcp_Stat, "tcpRtoMax", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 4, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_SIGN_INT4, &hdlr_tcp_Stat, "tcpMaxConn", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 5, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_tcp_Stat, "tcpActiveOpens", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 6, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_tcp_Stat, "tcpPassiveOpens", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_tcp_Stat, "tcpAttemptFails", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 8, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_tcp_Stat, "tcpEstabResets", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 9, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_tcp_Stat, "tcpCurrEstab", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 10, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_tcp_Stat, "tcpInSegs", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 11, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_tcp_Stat, "tcpOutSegs", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 12, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_tcp_Stat, "tcpRetransSegs", NULL},

    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 13, 1, 1, 0, 0, 0, 0, 0, 0}, {NUM_TCPCONNS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_tcpConnTable, "tcpConnState", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 13, 1, 2, 0, 0, 0, 0, 0, 0}, {NUM_TCPCONNS, 0, 0, 0}, NO_FILE, ACCESS_RD, 4, 4, OBJT_IP_ADDR, &hdlr_tcpConnTable, "tcpConnLocalAddress", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 13, 1, 3, 0, 0, 0, 0, 0, 0}, {NUM_TCPCONNS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_tcpConnTable, "tcpConnLocalPort", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 13, 1, 4, 0, 0, 0, 0, 0, 0}, {NUM_TCPCONNS, 0, 0, 0}, NO_FILE, ACCESS_RD, 4, 4, OBJT_IP_ADDR, &hdlr_tcpConnTable, "tcpConnRemAddress", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 13, 1, 5, 0, 0, 0, 0, 0, 0}, {NUM_TCPCONNS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_tcpConnTable, "tcpConnRemPort", NULL},

    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 14, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_tcp_Stat, "tcpInErrs", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 6, 15, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_tcp_Stat, "tcpOutRsts", NULL},

    // UDP  - RFC 1213
    {RFC_1213, {1, 3, 6, 1, 2, 1, 7, 1, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_udp_Stat, "udpInDatagrams", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 7, 2, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_udp_Stat, "udpNoPorts", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 7, 3, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_udp_Stat, "udpInErrors", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 7, 4, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_udp_Stat, "udpOutDatagrams", NULL},

    {RFC_1213, {1, 3, 6, 1, 2, 1, 7, 5, 1, 1, 0, 0, 0, 0, 0, 0}, {NUM_UDPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 4, 4, OBJT_IP_ADDR, &hdlr_table_udpTable, "udpLocalAddress", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 7, 5, 1, 2, 0, 0, 0, 0, 0, 0}, {NUM_UDPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_table_udpTable, "udpLocalPort", NULL},

    // SNMP - RFC 1213
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 1, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInPkts", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 2, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpOutPkts", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 3, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInBadVersions", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInBadCommunityNames", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 5, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInBadCommunityUses", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 6, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInASNParseErrs", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 8, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInTooBigs", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 9, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInNoSuchNames", NULL}    ,
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 10, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInBadValues", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 11, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInReadOnlys", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 12, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInGenErrs", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 13, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInTotalReqVars", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 14, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInTotalSetVars", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 15, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInGetRequests", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 16, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInGetNexts", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 17, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInSetRequests", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 18, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInGetResponses", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 19, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpInTraps", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 20, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpOutTooBigs", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 21, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpOutNoSuchNames", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 22, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpOutBadValues", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 24, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpOutGenErrs", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 25, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpOutGetRequests", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 26, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpOutGetNexts", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 27, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpOutSetRequests", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 28, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpOutGetResponses", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 29, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_snmp_Stat, "snmpOutTraps", NULL},
    {RFC_1213, {1, 3, 6, 1, 2, 1, 11, 30, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 1, 2, OBJT_INT1, &hdlr_snmp_Stat, "snmpEnableAuthenTraps", &tStatus1},

    // mcAtcNemaIoMapping - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 3, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_NEMA_INBITS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxNemaIoInputs", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 3, 2, 1, 1, 0}, {NUM_NEMA_INBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcNemaIoInputTable, "mcAtcNemaIoInputNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 3, 2, 1, 2, 0}, {NUM_NEMA_INBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOI_NUMIDS - 1, OBJT_INT1, &hdlr_table_mcAtcNemaIoInputTable, "mcAtcNemaIoInputFunction", &tInputFunction},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 3, 2, 1, 3, 0}, {NUM_NEMA_INBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcNemaIoInputTable, "mcAtcNemaIoInputIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 3, 2, 1, 4, 0}, {NUM_NEMA_INBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_table_mcAtcNemaIoInputTable, "mcAtcNemaIoInputRowLabel", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 3, 3, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_NEMA_OUTBITS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxNemaIoOutputs", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 3, 4, 1, 1, 0}, {NUM_NEMA_OUTBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcNemaIoOutputTable, "mcAtcNemaIoOutputNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 3, 4, 1, 2, 0}, {NUM_NEMA_OUTBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOO_NUMIDS - 1, OBJT_INT1, &hdlr_table_mcAtcNemaIoOutputTable, "mcAtcNemaIoOutputFunction", &tOutputFunction},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 3, 4, 1, 3, 0}, {NUM_NEMA_OUTBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcNemaIoOutputTable, "mcAtcNemaIoOutputIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 3, 4, 1, 4, 0}, {NUM_NEMA_OUTBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_table_mcAtcNemaIoOutputTable, "mcAtcNemaIoOutputRowLabel", NULL},

    // mcAtcTs2IoMapping
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_TS2_BIUS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxTs2Bius", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 2, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_TS2_BIU_INPUTS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxTs2BiuInputs", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 3, 1, 1, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_INPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcTs2IoInputTable, "mcAtcTs2IoBiuInNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 3, 1, 2, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_INPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcTs2IoInputTable, "mcAtcTs2IoInputNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 3, 1, 3, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_INPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOI_NUMIDS - 1, OBJT_INT1, &hdlr_table_mcAtcTs2IoInputTable, "mcAtcTs2IoInputFunction", &tInputFunction},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 3, 1, 4, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_INPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcTs2IoInputTable, "mcAtcTs2IoInputIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 3, 1, 5, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_INPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_table_mcAtcTs2IoInputTable, "mcAtcTs2IoInputRowLabel", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 4, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_TS2_BIU_OUTPUTS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxTs2IoBiuOutputs", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 5, 1, 1, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_OUTPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcTs2IoOutputTable, "mcAtcTs2IoBiuOutNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 5, 1, 2, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_OUTPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcTs2IoOutputTable, "mcAtcTs2IoOutputNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 5, 1, 3, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_OUTPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOO_NUMIDS - 1, OBJT_INT1, &hdlr_table_mcAtcTs2IoOutputTable, "mcAtcTs2IoOutputFunction", &tOutputFunction},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 5, 1, 4, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_OUTPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcTs2IoOutputTable, "mcAtcTs2IoOutputIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 4, 5, 1, 5, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_OUTPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_table_mcAtcTs2IoOutputTable, "mcAtcTs2IoOutputRowLabel", NULL},

    // mcAtcFioIoMapping
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 5, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_2070_2A_INBITS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxFioIoInputs", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 5, 2, 1, 1, 0}, {NUM_2070_2A_INBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcFioIoInputTable, "mcAtcFioIoInputNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 5, 2, 1, 2, 0}, {NUM_2070_2A_INBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOI_NUMIDS - 1, OBJT_INT1, &hdlr_table_mcAtcFioIoInputTable, "mcAtcFioIoInputFunction", &tInputFunction},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 5, 2, 1, 3, 0}, {NUM_2070_2A_INBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcFioIoInputTable, "mcAtcFioIoInputIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 5, 2, 1, 4, 0}, {NUM_2070_2A_INBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_table_mcAtcFioIoInputTable, "mcAtcFioIoInputRowLabel", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 5, 3, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_2070_2A_OUTBITS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxFioIoOutputs", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 5, 4, 1, 1, 0}, {NUM_2070_2A_OUTBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcFioIoOutputTable, "mcAtcFioIoOutputNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 5, 4, 1, 2, 0}, {NUM_2070_2A_OUTBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOO_NUMIDS - 1, OBJT_INT1, &hdlr_table_mcAtcFioIoOutputTable, "mcAtcFioIoOutputFunction", &tOutputFunction},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 5, 4, 1, 3, 0}, {NUM_2070_2A_OUTBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcFioIoOutputTable, "mcAtcFioIoOutputIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 5, 4, 1, 4, 0}, {NUM_2070_2A_OUTBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_table_mcAtcFioIoOutputTable, "mcAtcFioIoOutputRowLabel", NULL},

    // mcAtcItsIoMapping
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_ITS_SIUS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxItsSius", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 2, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_ITS_SIU_INPUTS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxItsSiuInputs", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 3, 1, 1, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_INPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcItsIoInputTable, "mcAtcItsIoSiuInNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 3, 1, 2, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_INPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcItsIoInputTable, "mcAtcItsIoInputNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 3, 1, 3, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_INPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOI_NUMIDS - 1, OBJT_INT1, &hdlr_table_mcAtcItsIoInputTable, "mcAtcItsIoInputFunction", &tInputFunction},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 3, 1, 4, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_INPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcItsIoInputTable, "mcAtcItsIoInputIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 3, 1, 5, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_INPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_table_mcAtcItsIoInputTable, "mcAtcItsIoInputRowLabel", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 4, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_ITS_SIU_OUTPUTS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxItsIoSiuOutputs", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 5, 1, 1, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_OUTPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcItsIoOutputTable, "mcAtcItsIoSiuOutNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 5, 1, 2, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_OUTPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcItsIoOutputTable, "mcAtcItsIoOutputNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 5, 1, 3, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_OUTPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOO_NUMIDS - 1, OBJT_INT1, &hdlr_table_mcAtcItsIoOutputTable, "mcAtcItsIoOutputFunction", &tOutputFunction},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 5, 1, 4, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_OUTPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcItsIoOutputTable, "mcAtcItsIoOutputIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 6, 5, 1, 5, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_OUTPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_table_mcAtcItsIoOutputTable, "mcAtcItsIoOutputRowLabel", NULL},

    // mcAtcItsDevices
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 7, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_ITS_DEVICES, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxItsDevices", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 7, 2, 1, 1, 0}, {MAX_ITS_DEVICES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcItsDeviceTable, "mcAtcItsDeviceNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 7, 2, 1, 2, 0}, {MAX_ITS_DEVICES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 2, OBJT_INT1, &hdlr_table_mcAtcItsDeviceTable, "mcAtcItsDevicePresent", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 7, 2, 1, 4, 0}, {MAX_ITS_DEVICES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcItsDeviceTable, "mcAtcItsDeviceStatus", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 7, 2, 1, 5, 0}, {MAX_ITS_DEVICES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcItsDeviceTable, "mcAtcItsDeviceFaultFrame", NULL},

    // mcAtcIoLogic
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_IOLOGIC_GATES, OBJT_INT1, &hdlr_mcAtcMaxIoLogicGates, "mcAtcMaxIoLogicGates", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 1, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicGateNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 2, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, 4, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicType", &tLogicType},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 3, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, 10, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicOutputMode", &tLogicOutputMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 4, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 1, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicOutputInvert", &tLogicInvert},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 5, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicOutputDelay", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 6, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicOutputExtension", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 7, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOGO_NUMIDS - 1, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicOutputFunction", &tLogicOutputFunc},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 8, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicOutputFunctionIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 9, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 1, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput1Invert", &tLogicInvert},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 10, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput1Delay", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 11, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput1Extension", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 12, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOGI_NUMIDS - 1, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput1Function", &tLogicInputFunc},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 13, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput1FunctionIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 14, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 1, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput2Invert", &tLogicInvert},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 15, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput2Delay", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 16, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput2Extension", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 17, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOGI_NUMIDS - 1, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput2Function", &tLogicInputFunc},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 18, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput2FunctionIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 19, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 1, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput3Invert", &tLogicInvert},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 20, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput3Delay", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 21, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput3Extension", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 22, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOGI_NUMIDS - 1, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput3Function", &tLogicInputFunc},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 23, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput3FunctionIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 24, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 1, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput4Invert", &tLogicInvert},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 25, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput4Delay", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 26, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput4Extension", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 27, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOGI_NUMIDS - 1, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput4Function", &tLogicInputFunc},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 28, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicInput4FunctionIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 8, 3, 1, 29, 0}, {NUM_IOLOGIC_GATES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, 4, OBJT_INT1, &hdlr_mcAtcIoLogicGateTable, "mcAtcIoLogicDelayExtendUnits", NULL},

    // mcAtcAuxSwitch
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 9, 1, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOI_NUMIDS - 1, OBJT_INT1, &hdlr_mcAtcAuxSwitchInputFunction, "mcAtcAuxSwitchInputFunction", &tInputFunction},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 2, 9, 2, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcAuxSwitchInputIndex, "mcAtcAuxSwitchInputIndex", NULL},

    // mcAtcCoord - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcCoordMaxTransitionCycles", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 2, 4, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcCoordPermStrategy", &tCoordPermStrat},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 2, 4, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcCoordOmitStrategy", &tCoordPermStrat},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 4, 1, 1, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcCoordSplitManualPermit", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 4, 1, 2, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcCoordSplitManualOmit", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 4, 1, 3, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcCoordSplitMinTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 4, 1, 4, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, SPLIT_MODE_OTHER, SPLIT_MODE_NONACT, OBJT_INT1, &hdlr_table_mcAtcCoordSplitTable, "mcAtcSplitMode", &tSplitMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 4, 1, 5, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_RESERVICE_COUNT_LIMIT, OBJT_INT1, &hdlr_table_mcAtcCoordSplitTable, "mcAtcCoordSplitMaxReserviceCount", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 4, 1, 6, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcCoordSplitBeginReservice", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 4, 1, 7, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcCoordSplitEndReservice", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 4, 1, 8, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 1, OBJT_INT1, &hdlr_table_mcAtcCoordSplitTable, "mcAtcCoordSplitPreferred", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 4, 1, 9, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcCoordSplitTable, "mcAtcCoordSplitGapOutTime", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 2, OBJT_INT1, &hdlr_mcAtcCoordSyncPoint, "mcAtcCoordSyncPoint", &tCoordSyncPoint},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 2, 3, OBJT_INT1, &hdlr_mcAtcCoordNoEarlyReturn, "mcAtcCoordNoEarlyReturn", &tCoordNoEarlyRet},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 7, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcLocalCycleTimer, "mcAtcLocalCycleTimer", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 1, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 5, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternCoordCorrectionMode", &tPatCoordCtionMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 2, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 6, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternCoordMaximumMode", &tPatCoordMaxMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 3, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternCoordForceMode", &tPatCoordForceMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 4, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcPatternCoordPermStrategy", &tCoordPermStrat},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 5, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcPatternCoordOmitStrategy", &tCoordPermStrat},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 6, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternCoordNoEarlyReturn", &tCoordNoEarlyRet},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 7, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, 4, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternPhaseTimingSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 8, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, 4, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternPhaseOptionSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 9, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, 4, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternVehOverlapSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 10, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternVehDetSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 11, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternVehDetDiagSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 12, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternPedDetSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 13, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternPedDetDiagSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 14, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternDetectorReset", &tPatDetReset},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 15, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_table_mcAtcPatternTable, "mcAtcPatternMax2Phases", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 16, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, 4, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternTexasDiamondType", &tPatTxDType},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 17, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternPrioritySet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 18, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternPedOverlapSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 19, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 1, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternCoordPercentValues", &tPatCoordPercent},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 20, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternActuatedCoordEnable", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 21, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternActuatedCoordValue", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 22, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_table_mcAtcPatternTable, "mcAtcPatternMax3Phases", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 23, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_table_mcAtcPatternTable, "mcAtcPatternMax4Phases", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 24, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, COORD_INC_PEDS_UNIT, COORD_INC_PEDS_ALLPEDS, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternCoverPeds", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 25, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, COORD_YIELD_UNIT, COORD_YIELD_ALLPERM, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternYieldStrategy", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 8, 1, 26, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_SPLITS, OBJT_INT1, &hdlr_table_mcAtcPatternTable, "mcAtcPatternSplitAdjustmentNumber", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 9, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 6, OBJT_INT1, &hdlr_mcAtcGlobalCoordMaximumMode, "mcAtcGlobalCoordMaximumMode", &tPatCoordMaxMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 10, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_RLP_ACTIVATIONS_PER_CYCLE, OBJT_INT1, &hdlr_mcAtcRedLightProtectionActivationsPerCycle, "mcAtcRedLightProtectionActivationsPerCycle", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 11, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_RLP_CYCLE_HEADWAY, OBJT_INT1, &hdlr_mcAtcRedLightProtectionCycleHeadway, "mcAtcRedLightProtectionCycleHeadway", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 12, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcCoordActCoordFloatingForceoffOverride, "mcAtcCoordActCoordFloatingForceoffOverride", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 13, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 510, OBJT_INT2, &hdlr_mcAtcLocalCycleLength, "mcAtcLocalCycleLength", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 14, 1, 0, 0, 0}, {MAX_PATTERNS, MAX_RINGS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 999, OBJT_INT2, &hdlr_mcAtcRingOffsetTable, "mcAtcRingOffsetV1", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 15, 1, 1, 0, 0}, {MAX_PATTERNS, MAX_RINGS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 999, OBJT_INT2, &hdlr_mcAtcRingOffsetTable, "mcAtcRingOffset", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 16, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, COORD_INC_PEDS_PEDCALLS, COORD_INC_PEDS_ALLPEDS, OBJT_INT1, &hdlr_mcAtcCoordCoverPeds, "mcAtcCoordCoverPeds", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 17, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, COORD_YIELD_STANDARD, COORD_YIELD_ALLPERM, OBJT_INT1, &hdlr_mcAtcCoordYieldStrategy, "mcAtcCoordYieldStrategy", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 18, 1, 1, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, ADJUSTMENT_ABSOLUTE, ADJUSTMENT_MAX, OBJT_INT1, &hdlr_table_bAdjustmentConstantsTable, "mcAtcAdjustmentType", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 19, 1, 1, 0, 0}, {MAX_PATTERNS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_bAdjustmentSplitTable, "mcAtcAdjustmentMinimum", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 19, 1, 2, 0, 0}, {MAX_PATTERNS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_bAdjustmentSplitTable, "mcAtcAdjustmentMaximum", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 20, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 100, OBJT_INT1, &hdlr_mcAtcCoordReducePhasePercent, "mcAtcCoordReducePhasePercent", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 3, 21, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcCoordExtendPhasePercent, "mcAtcCoordExtendPhasePercent", NULL},

    // mcAtcPedOverlap - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_OVERLAP_TABLES, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxPedOverlapSets", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_PED_OVERLAPS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxPedOverlaps", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 3, 1, 1, 0, 0}, {MAX_OVERLAP_TABLES, MAX_PED_OVERLAPS, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_OVERLAP_TABLES, OBJT_INT1, &hdlr_table_mcAtcPedOverlapTable, "mcAtcPedOverlapSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 3, 1, 2, 0, 0}, {MAX_OVERLAP_TABLES, MAX_PED_OVERLAPS, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_PED_OVERLAPS, OBJT_INT1, &hdlr_table_mcAtcPedOverlapTable, "mcAtcPedOverlapNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 3, 1, 3, 0, 0}, {MAX_OVERLAP_TABLES, MAX_PED_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PHASES, OBJT_OCTET, &hdlr_table_mcAtcPedOverlapTable, "mcAtcPedOverlapIncludedPhases", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 3, 1, 4, 0, 0}, {MAX_OVERLAP_TABLES, MAX_PED_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PHASES, OBJT_OCTET, &hdlr_table_mcAtcPedOverlapTable, "mcAtcPedOverlapExcludedPhases", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 3, 1, 5, 0, 0}, {MAX_OVERLAP_TABLES, MAX_PED_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcPedOverlapIntervals", &tPedOvlInterval},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 3, 1, 6, 0, 0}, {MAX_OVERLAP_TABLES, MAX_PED_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_table_mcAtcPedOverlapTable, "mcAtcPedOverlapCallPhases", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 3, 1, 7, 0, 0}, {MAX_OVERLAP_TABLES, MAX_PED_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcPedOverlapOptions", &tBitEnableOption},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 3, 1, 8, 0, 0}, {MAX_OVERLAP_TABLES, MAX_PED_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPedOverlapTable, "mcAtcPedOverlapWalkTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 3, 1, 9, 0, 0}, {MAX_OVERLAP_TABLES, MAX_PED_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPedOverlapTable, "mcAtcPedOverlapClearanceTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 3, 1, 10, 0, 0}, {MAX_OVERLAP_TABLES, MAX_PED_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 2, OBJT_INT1, &hdlr_table_mcAtcPedOverlapTable, "mcAtcPedOverlapRecall", &tStatus1},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 4, 3, 1, 11, 0, 0}, {MAX_OVERLAP_TABLES, MAX_PED_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPedOverlapTable, "mcAtcPedOverlapSteadyClearanceTime", NULL},

    // mcAtcPriority - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcPriorityGlobalEnable, "mcAtcPriorityGlobalEnable", &tPriorityBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 0x7FFFFFFF, OBJT_GAUGE, &hdlr_mcAtcPriorityGlobalNodeNumber, "mcAtcPriorityGlobalNodeNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 30, OBJT_DISPLAY_STR, &hdlr_mcAtcPriorityGlobalNodeName, "mcAtcPriorityGlobalNodeName", NULL}, // OCTET STRING
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPriorityGlobalHeadway, "mcAtcPriorityGlobalHeadway", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPriorityGlobalPreemptLockout, "mcAtcPriorityGlobalPreemptLockout", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_RW, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcPriorityGlobalOptions, "mcAtcPriorityGlobalOptions", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 11, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_TSP_TABLES, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxPriorityStrategySets", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 12, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_TSP_STRATEGIES, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxPriorityStrategies", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 1, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategySet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 2, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 4, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX, OBJT_INT2, &hdlr_table_mcAtcPriorityStrategyTable, "mcATCPriorityStrategyOptions", &tPriOptions},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 5, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX, OBJT_INT2, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyServicePhases", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 6, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyPhaseCalls", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 7, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyPhaseOmits", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 8, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyPedOmits", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 9, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyQueueJumpPhases", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 10, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyETA", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 11, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyInputFunction", &tPriInputFuction},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 12, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 16, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyInputFunctionIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 13, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 2, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyInputType", &tPriInputType},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 14, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyRequestMode", &tPriReqMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 15, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 5, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyCheckoutMode", &tPriCheckoutMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 16, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyCheckoutTimeout", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 17, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyMaxPresence", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 18, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyMaxPresenceClearTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 19, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyMinimumOnTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 20, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyMinimumOffTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 21, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyDelayTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 22, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyExtendTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 23, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyHeadwayTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 24, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyPreemptLockoutTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 25, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PHASES, OBJT_OCTET, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyMaximumReductionTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 26, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PHASES, OBJT_OCTET, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyMaximumExtensionTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 27, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PHASES, OBJT_OCTET, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyQueueJumpTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 28, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyArrivalWindow", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 29, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, NO_FILE, ACCESS_RD, 1, TSP_STRAT_STATE_MAX_STATE - 1, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyState", &tPriStrategyState},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 13, 1, 30, 0, 0}, {MAX_TSP_TABLES, MAX_TSP_STRATEGIES, 0, 0}, NO_FILE, ACCESS_RD, 1, TSP_STATE_IN_MAX_STATE, OBJT_INT1, &hdlr_table_mcAtcPriorityStrategyTable, "mcAtcPriorityStrategyInputState", &tPriInputState},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 14, 1, 1, 0, 0}, {MAX_TSP_STRATEGIES, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, 1, OBJT_INT1, &hdlr_table_mcAtcPriorityControlTable, "mcAtcPriorityControlRequest", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 14, 1, 2, 0, 0}, {MAX_TSP_STRATEGIES, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, 1, OBJT_INT1, &hdlr_table_mcAtcPriorityControlTable, "mcAtcPriorityControlCheckout", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 14, 1, 3, 0, 0}, {MAX_TSP_STRATEGIES, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityControlTable, "mcAtcPriorityControlETA", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 15, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, PRIORITY_IMAGE_MAX_ENTRIES, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxPriorityExtendedProcesses", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 16, 1, 1, 0, 0}, {PRIORITY_IMAGE_MAX_ENTRIES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityExtendedTable, "mcAtcPriorityExtendedNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 16, 1, 2, 0, 0}, {PRIORITY_IMAGE_MAX_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_EXTENDED_TSP, ACCESS_P, 0, 2, OBJT_INT1, &hdlr_table_mcAtcPriorityExtendedTable, "mcAtcPriorityExtendedType", &tPriExtType},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 16, 1, 3, 0, 0}, {PRIORITY_IMAGE_MAX_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_EXTENDED_TSP, ACCESS_P, 0, PRIORITY_IMAGE_NAME_MAX, OBJT_DISPLAY_STR, &hdlr_table_mcAtcPriorityExtendedTable, "mcAtcPriorityExtendedName", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 17, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, PRIORITY_IMAGE_MAX_IMAGES, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxPriorityExtendedProcessTable", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 18, 1, 1, 0, 0}, {PRIORITY_IMAGE_MAX_ENTRIES, PRIORITY_IMAGE_MAX_IMAGES, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityExtendedProcessTable, "mcAtcPriorityExtendedProcessNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 18, 1, 2, 0, 0}, {PRIORITY_IMAGE_MAX_ENTRIES, PRIORITY_IMAGE_MAX_IMAGES, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_mcAtcPriorityExtendedProcessTable, "mcAtcPriorityExtendedProcessImageNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 18, 1, 3, 0, 0}, {PRIORITY_IMAGE_MAX_ENTRIES, PRIORITY_IMAGE_MAX_IMAGES, 0, 0}, ENUM_FLASH_AREA_EXTENDED_TSP, ACCESS_P, 0, PRIORITY_IMAGE_MAX_SIZE, OBJT_DISPLAY_STR, &hdlr_table_mcAtcPriorityExtendedProcessTable, "mcAtcPriorityExtendedProcessImageSegment", NULL}, // Does not work

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 5, 19, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, TSP_STATE_MAX_STATE, OBJT_INT1, &hdlr_mcAtcPriorityState, "mcAtcPriorityState", &tPriState},

    // mcAtcDetectorVOSLog - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 6, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_LOG_DETS, OBJT_INT1, &hdlr_actionMax, "mcAtcDetVOSLogMaxDetectors", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 6, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_VOS_LOGS, OBJT_INT2, &hdlr_actionMax, "mcAtcDetVOSLogMaxEntries", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 6, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_VOS_LOGS, OBJT_INT2, &hdlr_mcAtcDetVOSLogNumEntries, "mcAtcDetVOSLogNumEntries", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 6, 5, 1, 1, 0, 0}, {MAX_VOS_LOGS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_VOS_LOGS, OBJT_INT2, &hdlr_mcAtcDetectorVOSLogTable, "mcAtcDetVOSLogEntryNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 6, 5, 1, 2, 0, 0}, {MAX_VOS_LOGS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, (12 + (6 * 32)) /*SIZE_VOS_ROW*/, OBJT_OCTET, &hdlr_mcAtcDetectorVOSLogTable, "mcAtcDetVOSLogEntryData", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 6, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcDetVOSLogStartSeqNum, "mcAtcDetVOSLogStartSeqNum", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 6, 7, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcDetVOSLogStartTimestamp, "mcAtcDetVOSLogStartTimestamp", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 6, 8, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_VOSLogClearAction, "mcAtcDetVOSLogClearSeqNum", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 6, 9, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_VOSLogClearAction, "mcAtcDetVOSLogClearTimestamp", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 6, 10, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_mcAtcDetVOSLogMode, "mcAtcDetVOSLogMode", &tLogMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 6, 11, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcDetVOSLogCombinedPeriods, "mcAtcDetVOSLogCombinedPeriods", NULL},

    // mcAtcSpeedTrap - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_SPEED_TRAPS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxSpeedTraps", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 3, 1, 1, 0, 0}, {MAX_SPEED_TRAPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSpeedTrapTable, "mcAtcSpeedTrapIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 3, 1, 2, 0, 0}, {MAX_SPEED_TRAPS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_DETECTORS, OBJT_INT1, &hdlr_mcAtcSpeedTrapTable, "mcAtcSpeedTrapDet1", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 3, 1, 3, 0, 0}, {MAX_SPEED_TRAPS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_DETECTORS, OBJT_INT1, &hdlr_mcAtcSpeedTrapTable, "mcAtcSpeedTrapDet2", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 3, 1, 4, 0, 0}, {MAX_SPEED_TRAPS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 9990, OBJT_INT2, &hdlr_mcAtcSpeedTrapTable, "mcAtcSpeedTrapDistance", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 3, 1, 5, 0, 0}, {MAX_SPEED_TRAPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpeedTrapTable, "mcAtcSpeedTrapAvgSpeed", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 3, 1, 6, 0, 0}, {MAX_SPEED_TRAPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_SPEED_BINS, OBJT_OCTET, &hdlr_mcAtcSpeedTrapTable, "mcAtcSpeedTrapBinCounts", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_SPEED_BINS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxSpeedBins", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 7, 1, 1, 0, 0}, {MAX_SPEED_BINS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSpeedBinTable, "mcAtcSpeedBinIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 7, 1, 2, 0, 0}, {MAX_SPEED_BINS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSpeedBinTable, "mcAtcSpeedBinRange", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 8, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_SPD_LOGS, OBJT_INT2, &hdlr_actionMax, "mcAtcSpeedTrapLogMaxEntries", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 9, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_SPD_LOGS, OBJT_INT2, &hdlr_mcAtcSpeedTrapLogNumEntries, "mcAtcSpeedTrapLogNumEntries", NULL}, // Do not works in omni

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 10, 1, 1, 0, 0}, {MAX_SPD_LOGS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_SPD_LOGS, OBJT_INT2, &hdlr_mcAtcSpeedTrapLogTable, "mcAtcSpeedTrapLogIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 10, 1, 2, 0, 0}, {MAX_SPD_LOGS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, (12 + (18 * 16)) /*SIZE_SPEED_ROW*/, OBJT_OCTET, &hdlr_mcAtcSpeedTrapLogTable, "mcAtcSpeedTrapLogEntryData", NULL}, // BADVALUE in omni

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 11, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcSpeedTrapLogStartSeqNum, "mcAtcSpeedTrapLogStartSeqNum", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 12, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcSpeedTrapLogStartTimestamp, "mcAtcSpeedTrapLogStartTimestamp", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 13, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcSpeedTrapLogClearSeqNum, "mcAtcSpeedTrapLogClearSeqNum", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 14, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcSpeedTrapLogClearTimestamp, "mcAtcSpeedTrapLogClearTimestamp", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 15, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_mcAtcSpeedTrapLogMode, "mcAtcSpeedTrapLogMode", &tLogMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 16, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpeedTrapLogPeriod, "mcAtcSpeedTrapLogPeriod", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 17, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcLogOptions, "mcAtcLogOptions", &tBitEnableOption},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 18, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcSpeedTrapSeqNum, "mcAtcSpeedTrapSeqNum", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 19, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcSpeedTrapTimestamp, "mcAtcSpeedTrapTimestamp", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 7, 20, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcSpeedTrapDuration, "mcAtcSpeedTrapDuration", NULL},

    // mcAtcUnit - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcSystemID, "mcAtcSystemID", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcUnitStartUpAllRed, "mcAtcUnitStartUpAllRed", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcUnitMinYellow, "mcAtcUnitMinYellow", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 7, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 1, OBJT_INT1, &hdlr_mcAtcTexasDiamondMode, "mcAtcTexasDiamondMode", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 8, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 2, 4, OBJT_INT1, &hdlr_mcAtcTexasDiamondType, "mcAtcTexasDiamondType", &tPatTxDType},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 9, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcNoStartVehCall, "mcAtcNoStartVehCall", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 10, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcNoStartPedCall, "mcAtcNoStartPedCall", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 11, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcStartupNextPhases, "mcAtcStartupNextPhases", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 12, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcOmniAlarmStatus, "mcAtcOmniAlarmStatus", &tOmniAlarm},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 13, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 1, OBJT_INT1, &hdlr_mcAtcDualPedestrianControl, "mcAtcDualPedestrianControl", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 14, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 0x7FFFFFFF, OBJT_INT4, &hdlr_mcAtcDocVersion, "mcAtcDocVersion", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 15, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcUnitIntervalAdvanceOverride", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 16, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, EXIT_AUTO_FLASH_ALL_RED_DISABLED, EXIT_AUTO_FLASH_ALL_RED_ENABLED, OBJT_INT1, &hdlr_mcAtcUnitExitAutoFlashAllRedEnable, "mcAtcUnitExitAutoFlashAllRedEnable", &tStatus1},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 17, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, EXIT_AUTO_FLASH_ALL_RED_MIN, EXIT_AUTO_FLASH_ALL_RED_MAX, OBJT_INT1, &hdlr_mcAtcUnitExitAutoFlashAllRedTime, "mcAtcUnitExitAutoFlashAllRedTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 8, 18, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcRequestedPatternStatus, "mcAtcRequestedPatternStatus", NULL},

    // mcAtcCycleMOELog - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 9, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_MOE_LOGS, OBJT_INT2, &hdlr_actionMax, "mcAtcCycleMOELogMaxEntries", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 9, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_MOE_LOGS, OBJT_INT2, &hdlr_mcAtcCycleMOELogNumEntries, "mcAtcCycleMOELogNumEntries", NULL}, // check functionality in OMNI

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 9, 3, 1, 1, 0, 0}, {MAX_MOE_LOGS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_MOE_LOGS, OBJT_INT2, &hdlr_mcAtcCycleMOELogTable, "mcAtcCycleMOELogEntryNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 9, 3, 1, 2, 0, 0}, {MAX_MOE_LOGS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, ((3 * 16) + 12) /*SIZE_MOE_ROW*/, OBJT_OCTET, &hdlr_mcAtcCycleMOELogTable, "mcAtcCycleMOELogEntryData", NULL}, // OMNI BADVALUE

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 9, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcCycleMOELogStartSeqNum, "mcAtcCycleMOELogStartSeqNum", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 9, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcCycleMOELogStartTimestamp, "mcAtcCycleMOELogStartTimestamp", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 9, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcCycleMOELogClearSeqNum, "mcAtcCycleMOELogClearSeqNum", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 9, 7, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcCycleMOELogClearTimestamp, "mcAtcCycleMOELogClearTimestamp", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 9, 8, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_mcAtcCycleMOELogMode, "mcAtcCycleMOELogMode", &tLogMode},

    // mcAtcControllerLog - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_CNTRL_LOG_EVENTS, OBJT_INT2, &hdlr_actionMax, "mcAtcControllerLogMaxEntries", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, NUM_CNTRL_LOG_EVENTS, OBJT_INT2, &hdlr_mcAtcControllerLogNumEntries, "mcAtcControllerLogNumEntries", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 3, 1, 1, 0, 0}, {NUM_CNTRL_LOG_EVENTS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_CNTRL_LOG_EVENTS, OBJT_INT2, &hdlr_mcAtcControllerLogTable, "mcAtcControllerLogEntryNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 3, 1, 2, 0, 0}, {NUM_CNTRL_LOG_EVENTS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, SIZE_CNTRL_LOG_ROW, OBJT_OCTET, &hdlr_mcAtcControllerLogTable, "mcAtcControllerLogEntryData", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_controllerLogReadAction, "mcAtcControllerLogStartSeqNum", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_controllerLogReadAction, "mcAtcControllerLogStartTimestamp", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_controllerLogClearAction, "mcAtcControllerLogClearSeqNum", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 7, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_controllerLogClearAction, "mcAtcControllerLogClearTimestamp", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 9, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaPowerOnOff, "mcAtcControllerLogEnaPowerOnOff", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 10, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaLowBattery, "mcAtcControllerLogEnaLowBattery", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 11, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaCycleFault, "mcAtcControllerLogEnaCycleFault", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 12, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaCoordFault, "mcAtcControllerLogEnaCoordFault", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 13, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaCoordFail, "mcAtcControllerLogEnaCoordFail", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 14, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaCycleFail, "mcAtcControllerLogEnaCycleFail", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 15, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaMMUflash, "mcAtcControllerLogEnaMMUflash", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 16, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaLocalFlash, "mcAtcControllerLogEnaLocalFlash", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 17, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaLocalFree, "mcAtcControllerLogEnaLocalFree", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 18, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaPreemptStatusChange, "mcAtcControllerLogEnaPreemptStatusChange", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 19, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaResponseFault, "mcAtcControllerLogEnaResponseFault", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 20, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaAlarmStatusChange, "mcAtcControllerLogEnaAlarmStatusChange", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 21, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaDoorStatusChange, "mcAtcControllerLogEnaDoorStatusChange", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 22, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaPatternChange, "mcAtcControllerLogEnaPatternChange", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 23, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaDetectorStatusChange, "mcAtcControllerLogEnaDetectorStatusChange", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 24, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaCommStatusChange, "mcAtcControllerLogEnaCommStatusChange", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 25, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaCommandChange, "mcAtcControllerLogEnaCommandChange", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 26, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaDataChangeKeyboard, "mcAtcControllerLogEnaDataChangeKeyboard", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 27, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaControllerDownload, "mcAtcControllerLogEnaControllerDownload", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 28, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaAccessCode, "mcAtcControllerLogEnaAccessCode", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 29, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaPriority, "mcAtcControllerLogEnaPriority", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 30, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaManCtrlEnable, "mcAtcControllerLogEnaManCtrlEnable", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 10, 31, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcControllerLogEnaStopTime, "mcAtcControllerLogEnaStopTime", &tStatus0},

    // mcAtcPhase - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_PHASE_TABLES, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxPhaseSets", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 1, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 2, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseWalk", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 3, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhasePedestrianClear", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 4, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseMinimumGreen", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 5, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhasePassage", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 6, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseMaximum1", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 7, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseMaximum2", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 8, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseYellowChange", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 9, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseRedClear", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 10, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseRedRevert", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 11, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseAddedInitial", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 12, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseMaximumInitial", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 13, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseTimeBeforeReduction", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 14, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseCarsBeforeReduction", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 15, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseTimeToReduce", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 16, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseReduceBy", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 17, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseMinimumGap", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 18, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseDynamicMaxLimit", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 19, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseDynamicMaxStep", NULL},      // -- OID ...,0x14 reserved, PhaseStartup only 1 entry
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 21, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcPhaseTable, "mcAtc1202PhaseOptions", &tPhaseOptions}, // -- OIDs ...,0x16 and ...,0x017 reserved, PhaseRing and PhaseConcurrency only 1 entry
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 24, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcPhaseTable, "mcAtcPhaseOptions2", &tPhaseOptions2},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 25, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseAlternateWalk", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 26, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseAdvanceWalk", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 27, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseDelayWalk", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 28, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseAlternatePassage", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 29, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseStartDelay", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 30, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseCondSvcMin", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 31, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseGreenClear", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 32, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseAlternatePedClear", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 33, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseAlternateMinGreen", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 34, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseMaximum3", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 35, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseMaximum4", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 36, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcRedLightProtectionTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 37, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcRedLightProtectionMaxApplications", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 38, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhasePedAlternateClearance", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 39, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtc1202PhasePedAlternateWalk", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 2, 1, 40, 0, 0}, {MAX_PHASE_TABLES, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTable, "mcAtcPhaseSteadyPedClearance", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 3, 1, 1, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcPhaseConfigTable, "mcAtc1202PhaseConfigOptions", &tPhaseConfig},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 3, 1, 2, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseConfigTable, "mcAtc1202PhaseStartup", &tPhaseStartup},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 3, 1, 3, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseConfigTable, "mcAtc1202PhaseRing", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 3, 1, 4, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 16, OBJT_OCTET, &hdlr_mcAtcPhaseConfigTable, "mcAtc1202PhaseConcurrency", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 4, 1, 1, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseControlTable, "mcAtcPhaseControlRedExtension", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 1, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2550, OBJT_INT2, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseWalkTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 2, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2550, OBJT_INT2, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhasePedClearTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 3, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2550, OBJT_INT2, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseMinimumGreenTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 4, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhasePassageTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 5, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2550, OBJT_INT2, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseMaxTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 6, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseYellowTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 7, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseRedClearTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 8, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseRedRevertTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 9, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2550, OBJT_INT2, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseInitialTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 10, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2550, OBJT_INT2, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseAdvanceWalkTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 11, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2550, OBJT_INT2, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseDelayWalkTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 12, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseStartDelayTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 13, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseGreenClearTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 14, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseGapReductionTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 15, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2550, OBJT_INT2, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseGreenElapsedTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 16, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseYellowElapsedTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 17, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseRedElapsedTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 18, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2550, OBJT_INT2, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseWalkElapsedTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 19, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2550, OBJT_INT2, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhasePedClearElapsedTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 20, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2550, OBJT_INT2, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseWaitTimer", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 21, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseGreenElapsedTimerSec", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 22, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseWalkElapsedTimerSec", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 23, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhasePedClearElapsedTimerSec", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 24, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhaseWaitTimerSec", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 11, 5, 1, 25, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPhaseTimersTable, "mcAtcPhasePedSteadyClrElapsedTimer", NULL},

    // mcAtcOverlap - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_OVERLAP_TABLES, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxOverlapSets", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 1, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcOverlapTable, "mcAtcOverlapSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 2, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 2, 6, OBJT_INT1, &hdlr_mcAtcOverlapTable, "mcAtcOverlapType", &tMcOverlapType},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 3, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PHASES, OBJT_OCTET, &hdlr_mcAtcOverlapTable, "mcAtcOverlapIncludedPhases", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 4, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PHASES, OBJT_OCTET, &hdlr_mcAtcOverlapTable, "mcAtcOverlapModifierPhases", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 5, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcOverlapTable, "mcAtcOverlapTrailGreen", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 6, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcOverlapTable, "mcAtcOverlapTrailYellow", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 7, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcOverlapTable, "mcAtcOverlapTrailRed", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 8, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcOverlapTable, "mcAtcOverlapStartDelay", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 9, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PHASES, OBJT_OCTET, &hdlr_mcAtcOverlapTable, "mcAtcOverlapExcludedPhases", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 10, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PHASES, OBJT_OCTET, &hdlr_mcAtcOverlapTable, "mcAtcOverlapExcludedPeds", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 11, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcOverlapTable, "mcAtcOverlapNoTrailGreenClearPhases", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 12, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcOverlapTable, "mcAtcOverlapCallPhases", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 13, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcOverlapTable, "mcAtcOverlapOptions", &tOverlapOptions},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 14, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PHASES, OBJT_OCTET, &hdlr_mcAtcOverlapTable, "mcAtcOverlapExcludedWalks", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 15, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 65535, OBJT_INT2, &hdlr_mcAtcOverlapTable, "mcAtcOverlapNoTrailGreenNextPhases", &tPhaseBitField}, // new object --pending
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 12, 2, 1, 16, 0, 0}, {MAX_OVERLAP_TABLES, MAX_VEH_OVERLAPS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PED_OVERLAPS, OBJT_OCTET, &hdlr_mcAtcOverlapTable, "mcAtcOverlapExcludedPedOverlaps", NULL},   // new object --pending

    // mcAtcDetector - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_DETECTOR_TABLES, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxVehicleDetectorSets", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 1, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtcVehicleDetectorSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 2, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorOptions", &tVehDetOptions},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 3, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorCallPhase", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 4, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorSwitchPhase", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 5, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorDelay", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 6, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorExtend", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 7, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorQueueLimit", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 8, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorNoActivity", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 9, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorMaxPresence", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 10, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorErraticCounts", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 11, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorFailTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 12, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 9990, OBJT_INT2, &hdlr_mcAtcVehicleDetectorTable, "mcAtcVehicleDetectorVOSLength", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 13, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtcVehicleDetectorOptions2", &tVehDetOptions2},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 14, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcVehicleDetectorTable, "mcAtcVehicleDetectorExtraCallPhases", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 15, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcVehicleDetectorTable, "mcAtcVehicleDetectorCallOverlaps", &tOverlapBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 16, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PHASES, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtcRedLightProtectionEnable", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 17, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 4000, OBJT_INT2, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorAvgVehicleLength", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 18, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorLength", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 2, 1, 19, 0, 0}, {MAX_DETECTOR_TABLES, MAX_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 4, OBJT_INT1, &hdlr_mcAtcVehicleDetectorTable, "mcAtc1202VehicleDetectorTravelMode", &tVehDetTravelMode},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 3, 1, 1, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorStatusTable, "mcAtcVehicleDetectorVolume", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 3, 1, 2, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorStatusTable, "mcAtcVehicleDetectorOccupancy", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 3, 1, 3, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcVehicleDetectorStatusTable, "mcAtcVehicleDetectorSpeed", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 4, 1, 1, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, 1, OBJT_INT1, &hdlr_mcAtcVehicleDetectorControlTable, "mcAtcVehicleDetectorControlState", &tStatus0},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 13, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcVehicleDataCollectionPeriod, "mcAtcVehicleDataCollectionPeriod", NULL},

    // mcAtcPedestrianDetector - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_DETECTOR_TABLES, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxPedestrianDetectorSets", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 2, 1, 1, 0, 0}, {MAX_DETECTOR_TABLES, MAX_PED_DETECTORS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPedestrianDetectorTable, "mcAtcPedestrianDetectorSet", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 2, 1, 2, 0, 0}, {MAX_DETECTOR_TABLES, MAX_PED_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PHASES, OBJT_INT1, &hdlr_mcAtcPedestrianDetectorTable, "mcAtc1202PedestrianDetectorCallPhase", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 2, 1, 3, 0, 0}, {MAX_DETECTOR_TABLES, MAX_PED_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPedestrianDetectorTable, "mcAtc1202PedestrianDetectorNoActivity", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 2, 1, 4, 0, 0}, {MAX_DETECTOR_TABLES, MAX_PED_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPedestrianDetectorTable, "mcAtc1202PedestrianDetectorMaxPresence", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 2, 1, 5, 0, 0}, {MAX_DETECTOR_TABLES, MAX_PED_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPedestrianDetectorTable, "mcAtc1202PedestrianDetectorErraticCounts", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 2, 1, 6, 0, 0}, {MAX_DETECTOR_TABLES, MAX_PED_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPedestrianDetectorTable, "mcAtcPedestrianDetectorOptions", &tPedDetOptions},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 2, 1, 7, 0, 0}, {MAX_DETECTOR_TABLES, MAX_PED_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcPedestrianDetectorTable, "mcAtcPedestrianDetectorExtraCallPhases", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 2, 1, 8, 0, 0}, {MAX_DETECTOR_TABLES, MAX_PED_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcPedestrianDetectorTable, "mcAtcPedestrianDetectorCallOverlaps", &tOverlapBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 2, 1, 9, 0, 0}, {MAX_DETECTOR_TABLES, MAX_PED_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPedestrianDetectorTable, "mcAtc1202PedestrianButtonPushTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 2, 1, 10, 0, 0}, {MAX_DETECTOR_TABLES, MAX_PED_DETECTORS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPedestrianDetectorTable, "mcAtc1202PedestrianDetectorOptions", &tPedDetOptionsStd},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 4, 1, 1, 0, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, 1, OBJT_INT1, &hdlr_mcAtcPedestrianDetectorControlTable, "mcAtcPedestrianDetectorControlState", &tStatus0},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 14, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcPedestrianDataCollectionPeriod, "mcAtcPedestrianDataCollectionPeriod", NULL},

    // mcAtcPreempt - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 1, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PED_OVERLAPS, OBJT_OCTET, &hdlr_mcAtcPreemptTable, "mcAtcPreemptTrackPedOverlap", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 2, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PED_OVERLAPS, OBJT_OCTET, &hdlr_mcAtcPreemptTable, "mcAtcPreemptDwellPedOverlap", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 3, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 15, OBJT_INT1, &hdlr_mcAtcPreemptTable, "mcAtcPreemptOptions", &tPreemptOptions},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 4, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PHASES, OBJT_OCTET, &hdlr_mcAtcPreemptTable, "mcAtcPreemptTrackPed", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 5, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PED_OVERLAPS, OBJT_OCTET, &hdlr_mcAtcPreemptTable, "mcAtcPreemptCyclingPedOverlap", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 6, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPreemptTable, "mcAtcPreemptExitPedClear", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 7, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPreemptTable, "mcAtcPreemptExitYellowChange", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 8, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPreemptTable, "mcAtcPreemptExitRedClear", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 9, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPreemptTable, "mcAtcPreemptMinTrackGreen", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 10, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPreemptTable, "mcAtcPreemptGateDownExtension", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 11, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPreemptTable, "mcAtcPreemptExtend", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 12, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPreemptTable, "mcAtcPreemptAdvancedTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 13, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPreemptTable, "mcAtcPreemptEnterSteadyPedClearance", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 16, 1, 1, 14, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcPreemptTable, "mcAtcPreemptExitSteadyPedClearance", NULL},

    // mcAtcCommunication - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 1, 1, 1, 0, 0}, {NUM_RS232PORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 8, OBJT_INT1, &hdlr_mcAtcSerialPortTable, "mcAtcSerialProtocol", &tSerialProtocol},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 1, 1, 2, 0, 0}, {NUM_RS232PORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PMPP_ADDRESS, OBJT_INT2, &hdlr_mcAtcSerialPortTable, "mcAtcSerialAddress", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 1, 1, 3, 0, 0}, {NUM_RS232PORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PMPP_GROUP_ADDRESS, OBJT_INT1, &hdlr_mcAtcSerialPortTable, "mcAtcSerialGroupAddress", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 1, 1, 4, 0, 0}, {NUM_RS232PORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 8, OBJT_INT1, &hdlr_mcAtcSerialPortTable, "mcAtcSerialSpeed", &tSerialSpeed},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 1, 1, 5, 0, 0}, {NUM_RS232PORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_mcAtcSerialPortTable, "mcAtcSerialParity", &tSerialParity},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 1, 1, 6, 0, 0}, {NUM_RS232PORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 7, 8, OBJT_INT1, &hdlr_mcAtcSerialPortTable, "mcAtcSerialDataBits", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 1, 1, 7, 0, 0}, {NUM_RS232PORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 2, OBJT_INT1, &hdlr_mcAtcSerialPortTable, "mcAtcSerialStopBits", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 1, 1, 8, 0, 0}, {NUM_RS232PORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_mcAtcSerialPortTable, "mcAtcSerialFlowControl", &tSerialFlowCtl},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 1, 1, 9, 0, 0}, {NUM_RS232PORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSerialPortTable, "mcAtcSerialCtsDelay", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 1, 1, 10, 0, 0}, {NUM_RS232PORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSerialPortTable, "mcAtcSerialRtsExtend", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 1, 1, 11, 0, 0}, {NUM_RS232PORTS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 255, OBJT_INT1, &hdlr_mcAtcSerialPortTable, "mcAtcSerialPortIndex", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 1, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetIpAddr", &tIpv4},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 2, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetNetmask", &tIpv4},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 3, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetGateway", &tIpv4},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 4, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetDnsServer", &tIpv4},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 5, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetDhcpMode", &tDHCPMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 6, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetDhcpStart", &tIpv4},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 7, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetDhcpEnd", &tIpv4},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 8, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 16, OBJT_OCTET, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetIpv6Addr", &tIpv6},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 9, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 128, OBJT_INT1, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetIpv6cidr", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 10, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 16, OBJT_OCTET, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetIpv6gateway", &tIpv6},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 11, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 16, OBJT_OCTET, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetIpv6dnsServer", &tIpv6},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 12, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, SIZE_HOSTNAME, OBJT_DISPLAY_STR, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetHostname", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 13, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetNtcipPort", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 14, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 2, OBJT_INT1, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetNtcipMode", &tTransportMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 15, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetAB3418Port", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 16, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 2, OBJT_INT1, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetAB3418Mode", &tTransportMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 17, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PMPP_ADDRESS, OBJT_INT2, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetAB3418Addr", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 18, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PMPP_GROUP_ADDRESS, OBJT_INT1, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetAB3418GroupAddr", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 19, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetP2pPort", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 20, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetFhpPort", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 21, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetFhpAddr", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 22, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_ETHERNET_FHP_CITY_CODE, OBJT_INT1, &hdlr_mcAtcEthernetPortTable, "mcAtcEthernetFhpCity", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 2, 1, 23, 0, 0}, {NUM_ETHERNETPORTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_FHP_FORWARDS, OBJT_OCTET, &hdlr_mcAtcEthernetPortTable, "u8McAtcEthernetFhpResponseForward", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcDownloadRequest, "mcAtcDownloadRequest", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 4, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_FHP_FORWARDS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxEthernetFhpForwardingEntries", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 4, 2, 1, 1, 0}, {MAX_FHP_FORWARDS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &mcAtcEthernetFhpForwardingTable, "mcAtcEthernetFhpForwardingEntryNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 4, 2, 1, 2, 0}, {MAX_FHP_FORWARDS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT32U_MAX, OBJT_GAUGE, &mcAtcEthernetFhpForwardingTable, "mcAtcEthernetFhpForwardingIpAddress", &tIpv4},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 17, 4, 2, 1, 3, 0}, {MAX_FHP_FORWARDS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &mcAtcEthernetFhpForwardingTable, "mcAtcEthernetFhpForwardingPort", NULL},

    // mcAtcTimeSync - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 18, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_mcAtcNtpIpAddr, "mcAtcNtpIpAddr", &tIpv4},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 18, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 16, OBJT_OCTET, &hdlr_mcAtcNtpIpv6Addr, "mcAtcNtpIpv6Addr", &tIpv6},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 18, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 23, OBJT_INT1, &hdlr_mcAtcNtpStartHour, "mcAtcNtpStartHour", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 18, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 59, OBJT_INT1, &hdlr_mcAtcNtpStartMinute, "mcAtcNtpStartMinute", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 18, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INTERVAL_HOUR_LIMIT, OBJT_INT1, &hdlr_mcAtcNtpIntervalHour, "mcAtcNtpIntervalHour", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 18, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INTERVAL_MINUTE_LIMIT, OBJT_INT1, &hdlr_mcAtcNtpIntervalMinute, "mcAtcNtpIntervalMinute", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 18, 7, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 23, OBJT_INT1, &hdlr_mcAtcGpsStartHour, "mcAtcGpsStartHour", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 18, 8, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 59, OBJT_INT1, &hdlr_mcAtcGpsStartMinute, "mcAtcGpsStartMinute", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 18, 9, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INTERVAL_HOUR_LIMIT, OBJT_INT1, &hdlr_mcAtcGpsIntervalHour, "mcAtcGpsIntervalHour", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 18, 10, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INTERVAL_MINUTE_LIMIT, OBJT_INT1, &hdlr_mcAtcGpsIntervalMinute, "mcAtcGpsIntervalMinute", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 18, 11, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcNtpServerOptions, "mcAtcNtpServerOptions", &tBitEnableOption},

    // mcAtcTimebase - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 19, 1, 1, 1, 0, 0}, {MAX_TBC_ACTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_mcAtcTimebaseTable, "mcAtcTimebaseDetectorReset", &tStatus0},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 19, 1, 1, 2, 0, 0}, {MAX_TBC_ACTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, LOG_MODE_TIMEBASE_NOACTION, LOG_MODE_TIMEBASE_STOP, OBJT_INT1, &hdlr_mcAtcTimebaseTable, "mcAtcTimebaseDetVOSLog", &tDeviceCtl},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 19, 1, 1, 3, 0, 0}, {MAX_TBC_ACTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, LOG_MODE_TIMEBASE_NOACTION, LOG_MODE_TIMEBASE_STOP, OBJT_INT1, &hdlr_mcAtcTimebaseTable, "mcAtcTimebaseSpeedTrapLog", &tDeviceCtl},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 19, 1, 1, 4, 0, 0}, {MAX_TBC_ACTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, LOG_MODE_TIMEBASE_NOACTION, LOG_MODE_TIMEBASE_STOP, OBJT_INT1, &hdlr_mcAtcTimebaseTable, "mcAtcTimebaseCycleMOELog", &tDeviceCtl},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 19, 1, 1, 5, 0, 0}, {MAX_TBC_ACTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcTimebaseTable, "mcAtcTimebaseSpecialFunction2", &tTBSpecialFunction2},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 19, 1, 1, 6, 0, 0}, {MAX_TBC_ACTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, LOG_MODE_TIMEBASE_NOACTION, LOG_MODE_TIMEBASE_STOP, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcTimebaseHRLog", &tDeviceCtl},

    // mcAtcMenuPermissions - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 20, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_SECURITY_USERS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxMenuPermissionsUsers", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 20, 2, 1, 1, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_SECURITY_USERS, OBJT_INT1, &hdlr_mcAtcMenuPermissionsUserTable, "mcAtcMenuPermissionsUserNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 20, 2, 1, 2, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX - 1, OBJT_INT2, &hdlr_mcAtcMenuPermissionsUserTable, "mcAtcMenuPermissionsUserID", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 20, 2, 1, 3, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcMenuPermissionsUserTable, "mcAtcMenuPermissionsUserPin", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 20, 2, 1, 4, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcMenuPermissionsUserTable, "mcAtcMenuPermissionsUserAccess", &tPermUserAccess},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 20, 2, 1, 5, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, SIZE_USERNAME, OBJT_DISPLAY_STR, &hdlr_mcAtcMenuPermissionsUserTable, "mcAtcMenuPermissionsUserName", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 20, 2, 1, 6, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, SIZE_FULLNAME, OBJT_DISPLAY_STR, &hdlr_mcAtcMenuPermissionsUserTable, "mcAtcMenuPermissionsUserFullName", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 20, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcMenuPermissionsOptions, "mcAtcMenuPermissionsOptions", &tFPSecurity},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 20, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcMenuPermissionsTimeout, "mcAtcMenuPermissionsTimeout", NULL},

    //  mcAtcCic - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 10, OBJT_INT1, &hdlr_mcAtcCicStatus, "mcAtcCicStatus", &tCicStatus},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, 3, OBJT_INT1, &hdlr_mcAtcCicGroupScalar, "mcAtcCicMode", &tCicMode}, // details
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX - 5, OBJT_INT1, &hdlr_mcAtcCicGroupScalar, "mcAtcCicPatternNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcCicGroupScalar, "mcAtcCicCycleTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX - 1, OBJT_INT1, &hdlr_mcAtcCicGroupScalar, "mcAtcCicOffsetTime", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 6, 1, 1, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcCicSplitTable, "mcAtcCicSplitNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 6, 1, 2, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcCicSplitTable, "mcAtcCicSplitTime", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 7, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcRemoteVolumeOccupancyPeriod, "mcAtcRemoteVolumeOccupancyPeriod", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 8, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, 3, OBJT_INT1, &hdlr_mcAtcCicGroupScalar, "mcAtcCicSyncReferenceMode", &tSyncRefMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 9, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, SECS_PER_DAY, OBJT_INT4, &hdlr_mcAtcCicGroupScalar, "mcAtcCicSyncReferenceTime", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 10, 1, 1, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcCicSplitUtilizationTable, "mcAtcCicSplitTimeUsedCurrent", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 10, 1, 2, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcCicSplitUtilizationTable, "mcAtcCicSplitPhaseStatusCurrent", &tSplitPhaseStatus},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 10, 1, 3, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcCicSplitUtilizationTable, "mcAtcCicSplitTimeUsedLast", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 10, 1, 4, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcCicSplitUtilizationTable, "mcAtcCicSplitPhaseStatusLast", &tSplitPhaseStatus},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 11, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcCicSplitSequenceNumberCurrent, "mcAtcCicSplitSequenceNumberCurrent", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 21, 12, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcCicSplitSequenceNumberLast, "mcAtcCicSplitSequenceNumberLast", NULL},

    // mcAtcHiResLog - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 22, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcHiResLogMode", &tLogMode},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 22, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcHiResLogEventEnable", &tHiResLogEvEnable},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 22, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MCCAIN_EVENTS_COUNT, OBJT_INT2, &hdlr_actionMax, "mcAtcHiResLogMaxMcCainEvents", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 22, 4, 1, 1, 0, 0}, {MCCAIN_EVENTS_COUNT, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MCCAIN_EVENTS_COUNT, OBJT_INT2, &hdlr_mcAtcHiResLogMcCainEventsTable, "mcAtcHiResLogMcCainEventID", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 22, 4, 1, 2, 0, 0}, {MCCAIN_EVENTS_COUNT, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, HIRES_DESCRIPTION_LENGTH, OBJT_DISPLAY_STR, &hdlr_mcAtcHiResLogMcCainEventsTable, "mcAtcHiResLogMcCainEventDescription", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 22, 4, 1, 3, 0, 0}, {MCCAIN_EVENTS_COUNT, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcHiResLogMcCainEventsTable, "mcAtcHiResLogMcCainEventDataLength", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 22, 4, 1, 4, 0, 0}, {MCCAIN_EVENTS_COUNT, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, /*HIRES_DESCRIPTION_LENGTH*/ HIRES_DESC_PARAMS_LENGTH, OBJT_DISPLAY_STR, &hdlr_mcAtcHiResLogMcCainEventsTable, "mcAtcHiResLogMcCainEventDataDetails"},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 22, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, /*HIRES_DESCRIPTION_LENGTH*/ HIRES_GLOSSARY_MAX_LENGTH, OBJT_OCTET, &hdlr_mcAtcHiResLogParameterAbbreviations, "mcAtcHiResLogParameterAbbreviations"},

    // mcAtcP2p - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, NUM_PEER_INPUTS, OBJT_INT1, &hdlr_actionMax, "mcAtcP2pMaxDevices", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 2, 1, 1, 0, 0}, {NUM_PEER_INPUTS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcP2pDeviceTable, "mcAtcP2pDeviceNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 2, 1, 2, 0, 0}, {NUM_PEER_INPUTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT32U_MAX, OBJT_INT4, &hdlr_mcAtcP2pDeviceTable, "mcAtcP2pPeerIpv4Address", &tIpv4},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 2, 1, 3, 0, 0}, {NUM_PEER_INPUTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT32U_MAX, OBJT_INT4, &hdlr_mcAtcP2pDeviceTable, "mcAtcP2pPeerSystemId", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 2, 1, 4, 0, 0}, {NUM_PEER_INPUTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcP2pDeviceTable, "mcAtcP2pPeerPort", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 2, 1, 5, 0, 0}, {NUM_PEER_INPUTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcP2pDeviceTable, "mcAtcP2pPeerMessageTimeout", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 2, 1, 6, 0, 0}, {NUM_PEER_INPUTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcP2pDeviceTable, "mcAtcP2pPeerRetries", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 2, 1, 7, 0, 0}, {NUM_PEER_INPUTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcP2pDeviceTable, "mcAtcP2pPeerHeartbeatTime", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, NUM_PEER_INPUT_FUNCTIONS, OBJT_INT1, &hdlr_actionMax, "mcAtcP2pMaxFunctions", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 4, 1, 1, 0, 0}, {NUM_PEER_INPUT_FUNCTIONS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcP2pPeerFunctionTable, "mcAtcP2pFunctionNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 4, 1, 2, 0, 0}, {NUM_PEER_INPUT_FUNCTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, NUM_PEER_INPUTS, OBJT_INT1, &hdlr_mcAtcP2pPeerFunctionTable, "mcAtcP2pFunctionDeviceNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 4, 1, 3, 0, 0}, {NUM_PEER_INPUT_FUNCTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOGI_NUMIDS - 1, OBJT_INT1, &hdlr_mcAtcP2pPeerFunctionTable, "mcAtcP2pFunctionRemoteFunction", &tLogicInputFunc},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 4, 1, 4, 0, 0}, {NUM_PEER_INPUT_FUNCTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcP2pPeerFunctionTable, "mcAtcP2pFunctionRemoteFunctionIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 4, 1, 5, 0, 0}, {NUM_PEER_INPUT_FUNCTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOGO_NUMIDS - 1, OBJT_INT1, &hdlr_mcAtcP2pPeerFunctionTable, "mcAtcP2pFunctionLocalFunction", &tLogicOutputFunc},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 4, 1, 6, 0, 0}, {NUM_PEER_INPUT_FUNCTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcP2pPeerFunctionTable, "mcAtcP2pFunctionLocalFunctionIndex", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 23, 4, 1, 7, 0, 0}, {NUM_PEER_INPUT_FUNCTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 1, OBJT_INT1, &hdlr_mcAtcP2pPeerFunctionTable, "mcAtcP2pFunctionDefaultState", NULL},

    // mcAtcSpat - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 1, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSpatOptions, "mcAtcSpatOptions", &tBitEnableOption},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 2, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT32U_MAX, OBJT_INT4, &hdlr_mcAtcSpatDestinationAddrIpv4, "mcAtcSpatDestinationAddrIpv4", &tIpv4},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 3, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 16, OBJT_OCTET, &hdlr_mcAtcSpatDestinationAddrIpv6, "mcAtcSpatDestinationAddrIpv6", &tIpv6},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 4, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpatDestinationPort, "mcAtcSpatDestinationPort", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 5, 1, 1, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSpatPhaseTimeToChangeTable, "mcAtcSpatPhaseTimeToChangeNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 5, 1, 2, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpatPhaseTimeToChangeTable, "mcAtcSpatVehMinTimeToChange", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 5, 1, 3, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpatPhaseTimeToChangeTable, "mcAtcSpatVehMaxTimeToChange", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 5, 1, 4, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpatPhaseTimeToChangeTable, "mcAtcSpatPedMinTimeToChange", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 5, 1, 5, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpatPhaseTimeToChangeTable, "mcAtcSpatPedMaxTimeToChange", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 6, 1, 1, 0}, {MAX_OVERLAPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSpatOvlpTimeToChangeTable, "mcAtcSpatOvlpTimeToChangeNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 6, 1, 2, 0}, {MAX_OVERLAPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpatOvlpTimeToChangeTable, "mcAtcSpatOvlpMinTimeToChange", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 6, 1, 3, 0}, {MAX_OVERLAPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpatOvlpTimeToChangeTable, "mcAtcSpatOvlpMaxTimeToChange", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 7, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpatIntersectionStatus, "mcAtcSpatIntersectionStatus", &tSpatIntStatus},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 8, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpatDiscontinuousChangeFlag, "mcAtcSpatDiscontinuousChangeFlag", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 9, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpatMessageSeqCounter, "mcAtcSpatMessageSeqCounter", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 10, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_SPAT_DESTINATIONS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxSpatDestinations", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 11, 1, 1, 0}, {MAX_SPAT_DESTINATIONS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSpatDestTable, "mcAtcSpatDestNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 11, 1, 2, 0}, {MAX_SPAT_DESTINATIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSpatDestTable, "mcAtcSpatDestOptions", &tBitEnableOption},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 11, 1, 3, 0}, {MAX_SPAT_DESTINATIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT32U_MAX, OBJT_INT4, &hdlr_mcAtcSpatDestTable, "mcAtcSpatDestAddrIpv4", &tIpv4},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 11, 1, 4, 0}, {MAX_SPAT_DESTINATIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 16, OBJT_OCTET, &hdlr_mcAtcSpatDestTable, "mcAtcSpatDestAddrIpv6", &tIpv6},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 24, 1, 11, 1, 5, 0}, {MAX_SPAT_DESTINATIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcSpatDestTable, "mcAtcSpatDestPort", NULL},

    // mcAtcBoston - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 25, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_BOSTON_SETTINGS, OBJT_INT1, &hdlr_actionMax, "mcAtcBostonMaxSettings", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 25, 2, 1, 1, 0, 0}, {MAX_BOSTON_SETTINGS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcBostonSettingsTable, "mcAtcBostonSettingsNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 25, 2, 1, 2, 0, 0}, {MAX_BOSTON_SETTINGS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcBostonSettingsTable, "mcAtcBostonPhaseMap", &tPhaseBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 25, 2, 1, 3, 0, 0}, {MAX_BOSTON_SETTINGS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcBostonSettingsTable, "mcAtcBostonDetMap", &tDetectorBitField},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 25, 2, 1, 4, 0, 0}, {MAX_BOSTON_SETTINGS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcBostonSettingsTable, "mcAtcBostonSysDetMap", &tDetectorBitField},

    // mcAtcBlocksDefinitions - McCain
    // Standard Blocks
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 26, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, NUM_STD_ASC_BLKS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxStandardBlocksDefinitions", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 26, 2, 1, 1, 0, 0}, {NUM_STD_ASC_BLKS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcStandardBlocksDefinitionTable, "mcAtcStandardBlocksDefinitionsNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 26, 2, 1, 2, 0, 0}, {NUM_STD_ASC_BLKS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_BLOCK_DEFINITION, OBJT_OCTET, &hdlr_mcAtcStandardBlocksDefinitionTable, "mcAtcStandardBlocksDefinition", NULL},

    // Omni Blocks
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 26, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, NUM_CUSTOM_ASC_BLKS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxOmniBlocksDefinitions", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 26, 4, 1, 1, 0, 0}, {NUM_CUSTOM_ASC_BLKS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcOmniBlocksDefinitionTable, "mcAtcOmniBlocksDefinitionsNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 26, 4, 1, 2, 0, 0}, {NUM_CUSTOM_ASC_BLKS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_BLOCK_DEFINITION, OBJT_OCTET, &hdlr_mcAtcOmniBlocksDefinitionTable, "mcAtcOmniBlocksDefinition", NULL},

    // mcAtcSecurity - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 27, 1, 1, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSecUserAuthTries, "mcAtcSecUserAuthTries", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 27, 1, 2, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSecUserAuthTimeWait, "mcAtcSecUserAuthTimeWait", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 27, 1, 3, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSecUserAuthTriesBlock, "mcAtcSecUserAuthTriesBlock", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 27, 1, 4, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcSecUserSessionTimeout, "mcAtcSecUserSessionTimeout", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 27, 1, 5, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_SECURITY_USERS, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcSecUserMaxUsers", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 27, 1, 6, 1, 1, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcSecUserNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 27, 1, 6, 1, 2, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_NONE, 0, SIZE_USERNAME, OBJT_DISPLAY_STR, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcSecUserName", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 27, 1, 6, 1, 3, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_NONE, 0, SIZE_USERKEY, OBJT_OCTET, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcSecUserKey", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 27, 1, 6, 1, 4, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_NONE, 0, SIZE_OCTET_STRING_CONFIG, OBJT_OCTET, &hdlr_mcAtcGenericDeprecatedObject, "mcAtcSecUserECabinetStatus", NULL},

    // mcAtcDayOfTheWeek - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 28, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_DOW_SCHEDULES, OBJT_INT1, &hdlr_mcAtcMaxDayOfWeekCurrentSchedule, "mcAtcMaxDayOfWeekCurrentSchedule", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 28, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_DOW_SCHEDULES, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxDayOfWeekScheduleEntries", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 28, 3, 1, 1, 0, 0}, {MAX_DOW_SCHEDULES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_DOW_SCHEDULES, OBJT_INT1, &hdlr_mcAtcDayOfWeekTable, "mcAtcDOWScheduleNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 28, 3, 1, 2, 0, 0}, {MAX_DOW_SCHEDULES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcAtcDayOfWeekTable, "mcAtcDayOfWeekDay", &tDayOfWeekBit},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 28, 3, 1, 3, 0, 0}, {MAX_DOW_SCHEDULES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 23, OBJT_INT1, &hdlr_mcAtcDayOfWeekTable, "mcAtcDayOfWeekHour", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 28, 3, 1, 4, 0, 0}, {MAX_DOW_SCHEDULES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 59, OBJT_INT1, &hdlr_mcAtcDayOfWeekTable, "mcAtcDayOfWeekMinute", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 28, 3, 1, 5, 0, 0}, {MAX_DOW_SCHEDULES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_mcAtcDayOfWeekTable, "mcAtcDayOfWeekFunctionSets", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 28, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 38 /*DOWFUNC_NUMFUNCTIONS*/, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxDOWFunctions", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 28, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_DOW_FUNCTION_SETS, OBJT_INT1, &hdlr_actionMax, "mcAtcMaxDOWFunctionSets", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 28, 6, 1, 1, 0, 0}, {MAX_DOW_FUNCTION_SETS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_DOW_FUNCTION_SETS, OBJT_INT1, &hdlr_mcAtcDayOfWeekFunctionTable, "mcAtcDOWFunctionNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 28, 6, 1, 2, 0, 0}, {MAX_DOW_FUNCTION_SETS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_DOW_FUNCTION_OCTET_LEN, OBJT_OCTET, &hdlr_mcAtcDayOfWeekFunctionTable, "mcAtcDOWFunctions", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 28, 6, 1, 3, 0, 0}, {MAX_DOW_FUNCTION_SETS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_DOW_FUNCTION_VALUES_OCTET_LEN, OBJT_OCTET, &hdlr_mcAtcDayOfWeekFunctionTable, "mcAtcDOWFunctionValues", NULL},

    // mcAtcBotStatus - McCain
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_BOT_ALARMS, OBJT_INT1, &hdlr_actionMax, "mcAtcBotMaxAlarms", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 2, 1, 1, 0, 0}, {MAX_BOT_ALARMS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_BOT_ALARMS, OBJT_INT1, &hdlr_mcAtcBotStatus, "mcAtcBotStatusAlarmNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 2, 1, 2, 0, 0}, {MAX_BOT_ALARMS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_mcAtcBotStatus, "mcAtcBotStatusAlarm", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_mcAtcBotExcessiveLockoutTime, "mcAtcBotExcessiveLockoutTime", NULL},

    // {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 4, 1, 1, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_SECURITY_USERS, OBJT_INT1, &hdlr_mcAtcBotUser, "mcAtcBotUserLoginNumber", NULL},
    // {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 4, 1, 2, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, HIRES_MAX_EVENT_DATA_SIZE, OBJT_OCTET, &hdlr_mcAtcBotUser, "mcAtcBotUserLoginUsername", NULL},
    // {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 4, 1, 3, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_mcAtcBotUser, "mcAtcBotUserLastLogin", NULL},
    // {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 4, 1, 4, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_mcAtcBotUser, "mcAtcBotUserAverageLogin", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_LAMPS, OBJT_INT1, &hdlr_actionMax, "mcAtcBotMaxLamps", NULL},

    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 6, 1, 1, 0, 0}, {MAX_LAMP_GROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_LAMP_GROUPS, OBJT_INT1, &hdlr_mcAtcBotLamp, "mcAtcBotLampGroupNumber", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 6, 1, 2, 0, 0}, {MAX_LAMP_GROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_mcAtcBotLamp, "mcAtcBotLampOutDetected", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 6, 1, 3, 0, 0}, {MAX_LAMP_GROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_mcAtcBotLamp, "mcAtcBotLampErratic", NULL},
    {MCCAIN, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 2, 29, 6, 1, 4, 0, 0}, {MAX_LAMP_GROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_INT4, &hdlr_mcAtcBotLamp, "mcAtcBotLampPersistentCurrent", NULL},
    //------------------------------------------------------------------- MCRMCIOMAPPING-------------------------------------------------------------------------
    // MCRMCNEMAIOMAPPING
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 3, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxNemaIoInputs", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 3, 2, 1, 1, 0}, {NUM_NEMA_INBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcNemaIoInputTable, "mcRmcNemaIoInputNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 3, 2, 1, 2, 0}, {NUM_NEMA_INBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, 8, OBJT_INT1, &hdlr_mcRmcNemaIoInputTable, "mcRmcNemaIoInputFunction", &tRampInputFunction},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 3, 2, 1, 3, 0}, {NUM_NEMA_INBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcNemaIoInputTable, "mcRmcNemaIoInputIndex", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 3, 2, 1, 4, 0}, {NUM_NEMA_INBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_mcRmcNemaIoInputTable, "mcRmcNemaIoInputRowLabel", NULL},

    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 3, 3, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxNemaIoOutputs", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 3, 4, 1, 1, 0}, {NUM_NEMA_OUTBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcNemaIoOutputTable, "mcRmcNemaIoOutputNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 3, 4, 1, 2, 0}, {NUM_NEMA_OUTBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, 7, OBJT_INT1, &hdlr_mcRmcNemaIoOutputTable, "mcRmcNemaIoOutputFunction", &tRampOutputFunction},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 3, 4, 1, 3, 0}, {NUM_NEMA_OUTBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcNemaIoOutputTable, "mcRmcNemaIoOutputIndex", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 3, 4, 1, 4, 0}, {NUM_NEMA_OUTBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_mcRmcNemaIoOutputTable, "mcRmcNemaIoOutputRowLabel", NULL},

    // MCRMCTS2IOMAPPING
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_TS2_BIUS, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxTs2Bius", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 2, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_TS2_BIU_INPUTS, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxTs2BiuInputs", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 3, 1, 1, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_INPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcTs2IoInputTable, "mcRmcTs2IoBiuInNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 3, 1, 2, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_INPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcTs2IoInputTable, "mcRmcTs2IoInputNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 3, 1, 3, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_INPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOI_NUMIDS - 1, OBJT_INT1, &hdlr_mcRmcTs2IoInputTable, "mcRmcTs2IoInputFunction", &tRampInputFunction}, // needs mcRmc direction
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 3, 1, 4, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_INPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcTs2IoInputTable, "mcRmcTs2IoInputIndex", NULL},                        // needs mcRmc direction
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 3, 1, 5, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_INPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_mcRmcTs2IoInputTable, "mcRmcTs2IoInputRowLabel", NULL},                                 // The code needs to be more standard

    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 4, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_TS2_BIU_OUTPUTS, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxTs2IoBiuOutputs", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 5, 1, 1, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_OUTPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcTs2IoOutputTable, "mcRmcTs2IoBiuOutNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 5, 1, 2, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_OUTPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcTs2IoOutputTable, "mcRmcTs2IoOutputNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 5, 1, 3, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_OUTPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOO_NUMIDS - 1, OBJT_INT1, &hdlr_mcRmcTs2IoOutputTable, "mcRmcTs2IoOutputFunction", &tRampOutputFunction}, // needs mcRmc direction
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 5, 1, 4, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_OUTPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcTs2IoOutputTable, "mcRmcTs2IoOutputIndex", NULL},                         // needs mcRmc direction
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 4, 5, 1, 5, 0}, {NUM_TS2_BIUS, NUM_TS2_BIU_OUTPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_OCTET, &hdlr_mcRmcTs2IoOutputTable, "mcRmcTs2IoOutputRowLabel", NULL},                                        // The code needs to be more MCCAIN_RMrd

    // MCRMCFIOIOMAPPING
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 5, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_2070_2A_INBITS, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxFioIoInputs", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 5, 2, 1, 1, 0}, {NUM_2070_2A_INBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcFioIoInputTable, "mcRmcFioIoInputNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 5, 2, 1, 2, 0}, {NUM_2070_2A_INBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOI_NUMIDS - 1, OBJT_INT1, &hdlr_mcRmcFioIoInputTable, "mcRmcFioIoInputFunction", &tRampInputFunction},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 5, 2, 1, 3, 0}, {NUM_2070_2A_INBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcFioIoInputTable, "mcRmcFioIoInputIndex", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 5, 2, 1, 4, 0}, {NUM_2070_2A_INBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_mcRmcFioIoInputTable, "mcRmcFioIoInputRowLabel", NULL},

    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 5, 3, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_2070_2A_OUTBITS, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxFioIoOutputs", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 5, 4, 1, 1, 0}, {NUM_2070_2A_OUTBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcFioIoOutputTable, "mcRmcFioIoOutputNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 5, 4, 1, 2, 0}, {NUM_2070_2A_OUTBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOO_NUMIDS - 1, OBJT_INT1, &hdlr_mcRmcFioIoOutputTable, "mcRmcFioIoOutputFunction", &tRampOutputFunction},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 5, 4, 1, 3, 0}, {NUM_2070_2A_OUTBITS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcFioIoOutputTable, "mcRmcFioIoOutputIndex", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 5, 4, 1, 4, 0}, {NUM_2070_2A_OUTBITS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_mcRmcFioIoOutputTable, "mcRmcFioIoOutputRowLabel", NULL},

    // MCRMCITSIOMAPPING
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_ITS_SIUS, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxItsSius", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 2, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_ITS_SIU_INPUTS, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxItsSiuInputs", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 3, 1, 1, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_INPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcItsIoInputTable, "mcRmcItsIoSiuInNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 3, 1, 2, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_INPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcItsIoInputTable, "mcRmcItsIoInputNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 3, 1, 3, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_INPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOI_NUMIDS - 1, OBJT_INT1, &hdlr_mcRmcItsIoInputTable, "mcRmcItsIoInputFunction", &tRampInputFunction},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 3, 1, 4, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_INPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcItsIoInputTable, "mcRmcItsIoInputIndex", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 3, 1, 5, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_INPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_mcRmcItsIoInputTable, "mcRmcItsIoInputRowLabel", NULL},

    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 4, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_ITS_SIU_OUTPUTS, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxItsIoSiuOutputs", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 5, 1, 1, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_OUTPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcItsIoOutputTable, "mcRmcItsIoSiuOutNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 5, 1, 2, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_OUTPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcItsIoOutputTable, "mcRmcItsIoOutputNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 5, 1, 3, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_OUTPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, IOO_NUMIDS - 1, OBJT_INT1, &hdlr_mcRmcItsIoOutputTable, "mcRmcItsIoOutputFunction", &tRampOutputFunction},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 5, 1, 4, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_OUTPUTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcItsIoOutputTable, "mcRmcItsIoOutputIndex", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 6, 5, 1, 5, 0}, {NUM_ITS_SIUS, NUM_ITS_SIU_OUTPUTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_DISPLAY_STR, &hdlr_mcRmcItsIoOutputTable, "mcRmcItsIoOutputRowLabel", NULL},

    // MCRMCITSDEVICESIOMAPPING
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 7, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_ITS_DEVICES, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxItsDevices", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 7, 2, 1, 1, 0}, {MAX_ITS_DEVICES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcItsDeviceTable, "mcRmcItsDeviceNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 7, 2, 1, 2, 0}, {MAX_ITS_DEVICES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 2, OBJT_INT1, &hdlr_mcRmcItsDeviceTable, "mcRmcItsDevicePresent", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 7, 2, 1, 4, 0}, {MAX_ITS_DEVICES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 3, OBJT_INT1, &hdlr_mcRmcItsDeviceTable, "mcRmcItsDeviceStatus", &tDevStatus},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 2, 7, 2, 1, 5, 0}, {MAX_ITS_DEVICES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcItsDeviceTable, "mcRmcItsDeviceFaultFrame", NULL},

    // Standard Ramp meter Blocks
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 3, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, NUM_STD_RAMP_ASC_BLKS, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxStandardRampBlockDefinitions", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 3, 2, 1, 1, 0, 0}, {NUM_STD_RAMP_ASC_BLKS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcStandardRampBlocksDefinitionTable, "mcRmcStandardRampBlocksDefinitionNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 3, 2, 1, 2, 0, 0}, {NUM_STD_RAMP_ASC_BLKS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_BLOCK_DEFINITION, OBJT_OCTET, &hdlr_mcRmcStandardRampBlocksDefinitionTable, "mcRmcStandardRampBlocksDefinition", NULL},

    // Omni Ramp meter Blocks
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 3, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, NUM_CUSTOM_RAMP_ASC_BLKS, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxOmniRampBlockDefinitions", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 3, 4, 1, 1, 0, 0}, {NUM_CUSTOM_RAMP_ASC_BLKS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcOmniRampBlocksDefinitionTable, "mcRmcOmniRampBlocksDefinitionNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 3, 4, 1, 2, 0, 0}, {NUM_CUSTOM_RAMP_ASC_BLKS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_BLOCK_DEFINITION, OBJT_OCTET, &hdlr_mcRmcOmniRampBlocksDefinitionTable, "mcRmcOmniRampBlocksDefinition", NULL},

    // Omni Ramp Aux Outputs
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 4, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_RAMP_AUX_OUTPUTS, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxAuxOutputs", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 4, 2, 1, 1, 0, 0}, {MAX_RAMP_AUX_OUTPUTS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_RAMP_AUX_OUTPUTS, OBJT_INT1, &hdlr_mcRmcAuxOutputTable, "mcRmcAuxOutputNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 4, 2, 1, 2, 0, 0}, {MAX_RAMP_AUX_OUTPUTS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, 1, OBJT_INT1, &hdlr_mcRmcAuxOutputTable, "mcRmcAuxOutputState", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 4, 2, 1, 3, 0, 0}, {MAX_RAMP_AUX_OUTPUTS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcAuxOutputTable, "mcRmcAuxOutputOnDelay", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 4, 2, 1, 4, 0, 0}, {MAX_RAMP_AUX_OUTPUTS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_mcRmcAuxOutputTable, "mcRmcAuxOutputOffDelay", NULL},

    // Omni Ramp Queue
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 5, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_QUEUES, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxRampQueues", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 5, 2, 1, 1, 0, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_QUEUES, OBJT_INT1, &hdlr_mcRmcQueueStatusTable, "mcRmcQueueStatusNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 5, 2, 1, 2, 0, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 1, OBJT_INT1, &hdlr_mcRmcQueueStatusTable, "mcRmcQueueStatusState", &tStatus0},

    // Omni Metered Lane
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 6, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_RAMP_LANES, OBJT_INT1, &hdlr_actionMax, "mcRmcMaxRampLanes", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 6, 2, 1, 1, 0, 0}, {MAX_RAMP_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_RAMP_LANES, OBJT_INT1, &hdlr_mcRmcMeterControlTable, "mcRmcMeteredLaneNumber", NULL},
    {MCCAIN_RM, {1, 3, 6, 1, 4, 1, 1206, 3, 21, 3, 6, 2, 1, 2, 0, 0}, {MAX_RAMP_LANES, 0, 0, 0}, NO_FILE, ACCESS_RW, 1, 5, OBJT_INT1, &hdlr_mcRmcMeterControlTable, "mcRmcRequestCommandSource", NULL},

    //--------------------------------------------------------------------------------------------------------------------------------------------

    // stmp - NTCIP 1103
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 1, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 484, SIZE_COMMSBLOCK, OBJT_INT2, &hdlr_actionMax, "snmpmaxPacketSize", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 1, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinPkts", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 2, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutPkts", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 6, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinParseErrs", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 8, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinTooBigs", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 9, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinNoSuchNames", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 10, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinBadValues", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 11, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinReadOnlys", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 12, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinGenErrs", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 15, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinGetRequests", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 16, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinGetNexts", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 17, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinSetRequests", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 18, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinGetResponses", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 20, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutTooBigs", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 21, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutNoSuchNames", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 22, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutBadValues", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 23, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutReadOnly", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 24, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutGenError", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 25, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutGetRequests", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 26, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutGetNexts", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 27, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutSetRequests", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 28, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutGetResponses", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 31, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinSetRequestsNoReply", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 32, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinSetResponses", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 33, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpinErrorResponses", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 34, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutSetRequestsNoReply", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 35, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutSetResponses", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 3, 1, 36, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_stmp_Stat, "stmpoutErrorResponses", NULL},

    // LogicalName - NTCIP 1103
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 4, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_LOGNAMETRANS, OBJT_INT1, &hdlr_actionMax, "logicalNameTranslationTablemaxEntries", NULL}, // LOGICAL NAME GROUP NTCIP 1103
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 4, 2, 1, 1, 0}, {NUM_LOGNAMETRANS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_logicalNameTranslationTable, "logicalNameTranslationindex", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 4, 2, 1, 2, 0}, {NUM_LOGNAMETRANS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, SIZE_LOGNAMETRANS, OBJT_DISPLAY_STR, &hdlr_logicalNameTranslationTable, "logicalNameTranslationlogicalName", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 4, 2, 1, 3, 0}, {NUM_LOGNAMETRANS, 0, 0, 0}, NO_FILE, ACCESS_RW, 4, 4, OBJT_IP_ADDR, &hdlr_logicalNameTranslationTable, "logicalNameTranslationnetworkAddress", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 1, 7, 4, 2, 1, 4, 0}, {NUM_LOGNAMETRANS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_logicalNameTranslationTable, "logicalNameTranslationstatus", NULL},

    // profilesSTMP
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 2, 2, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 65535, OBJT_INT2, &hdlr_dynamicObjectPersistence, "dynamicObjectPersistence", NULL},
    {NTCIP_1103, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 2, 2, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_DYNAMIC_OBJECTS, ACCESS_RD, 0, 65535, OBJT_INT2, &hdlr_dynamicObjectTableConfigID, "dynamicObjectTableConfigID", NULL},

    // hdlcGroupAddress - NTCIP 1201
    {NTCIP_1201, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 2, 3, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_HDLCGRPADDR, OBJT_INT1, &hdlr_actionMax, "maxGroupAddresses", NULL},
    {NTCIP_1201, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 2, 3, 2, 1, 1, 0, 0}, {NUM_HDLCGRPADDR, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_hdlcGroupAddressTable, "hdlcGroupAddressIndex", NULL},
    {NTCIP_1201, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 2, 3, 2, 1, 3, 0, 0}, {NUM_HDLCGRPADDR, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 62, OBJT_INT1, &hdlr_hdlcGroupAddressTable, "hdlcGroupAddressNumber", NULL},

    // dynObjMgmt
    {NTCIP_1103a, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 3, 1, 1, 1, 0, 0, 0}, {MAX_DYNOBJS, MAX_DYNOBJ_VARS, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_DYNOBJS, OBJT_INT1, &hdlr_dynObjDefTable, "dynObjNumber", NULL},
    {NTCIP_1103a, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 3, 1, 1, 2, 0, 0, 0}, {MAX_DYNOBJS, MAX_DYNOBJ_VARS, 0, 0}, NO_FILE, ACCESS_RD, 1, 255, OBJT_INT1, &hdlr_dynObjDefTable, "dynObjIndex", NULL},
    {NTCIP_1103a, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 3, 1, 1, 3, 0, 0, 0}, {MAX_DYNOBJS, MAX_DYNOBJ_VARS, 0, 0}, ENUM_FLASH_AREA_DYNAMIC_OBJECTS, ACCESS_P, 0, SIZE_DYNOBJ_VAR, OBJT_OID, &hdlr_dynObjDefTable, "dynObjVariable", NULL},
    {NTCIP_1103a, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 3, 3, 1, 1, 0, 0, 0}, {MAX_DYNOBJS, 0, 0, 0}, ENUM_FLASH_AREA_DYNAMIC_OBJECTS, ACCESS_P, 0, SIZE_DYNCFG_OWNER, OBJT_DISPLAY_STR, &hdlr_dynObjCfgOwner, "dynObjConfigOwner", NULL},
    {NTCIP_1103a, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 3, 3, 1, 2, 0, 0, 0}, {MAX_DYNOBJS, 0, 0, 0}, ENUM_FLASH_AREA_DYNAMIC_OBJECTS, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_dynObjCfgStatus, "dynObjConfigStatus", &tConfStatus},
    {NTCIP_1103a, {1, 3, 6, 1, 4, 1, 1206, 4, 1, 3, 4, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_DYNOBJ_VARS, OBJT_INT1, &hdlr_actionMax, "dynObjDefTableMaxEntries", NULL},

    // phase - NTCIP 1202
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 2, MAX_PHASES, OBJT_INT1, &hdlr_actionMax, "maxPhases", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 1, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 2, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseWalk", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 3, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phasePedestrianClear", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 4, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseMinimumGreen", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 5, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phasePassage", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 6, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseMaximum1", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 7, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseMaximum2", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 8, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseYellowChange", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 9, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseRedClear", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 10, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseRedRevert", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 11, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseAddedInitial", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 12, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseMaximumInitial", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 13, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseTimeBeforeReduction", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 14, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseCarsBeforeReduction", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 15, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseTimeToReduce", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 16, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseReduceBy", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 17, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseMinimumGap", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 18, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseDynamicMaxLimit", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 19, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseDynamicMaxStep", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 20, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 2, 6, OBJT_INT1, &hdlr_phaseTable, "phaseStartup", &tPhaseStartup},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 21, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT16U_MAX, OBJT_INT2, &hdlr_phaseTable, "phaseOptions", &tPhaseOptions},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 22, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseRing", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 23, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, 16, OBJT_OCTET, &hdlr_phaseTable, "phaseConcurrency", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 24, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, 6000, OBJT_INT2, &hdlr_phaseTable, "phaseMaximum3", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 25, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseYellowandRedChangeTimeBeforeEndPedClear", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 26, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RW, 1, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phasePedWalkService", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 27, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseDontWalkRevert", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 28, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phasePedAlternateClearance", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 29, 0, 0}, {MAX_PHASES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phasePedAlternateWalk", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 30, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phasePedAdvanceWalkTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 31, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phasePedDelayTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 32, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, 128, OBJT_INT1, &hdlr_phaseTable, "phaseAdvWarnGrnStartTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 33, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseAdvWarnRedStartTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 2, 1, 34, 0, 0}, {MAX_PHASES, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseTable, "phaseAltMinTimeTransition", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_PHASEGROUPS, OBJT_INT1, &hdlr_actionMax, "maxPhaseGroups", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 4, 1, 1, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_phaseStatusGroupTable, "phaseStatusGroupNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 4, 1, 2, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseStatusGroupTable, "phaseStatusGroupReds", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 4, 1, 3, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseStatusGroupTable, "phaseStatusGroupYellows", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 4, 1, 4, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseStatusGroupTable, "phaseStatusGroupGreens", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 4, 1, 5, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseStatusGroupTable, "phaseStatusGroupDontWalks", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 4, 1, 6, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseStatusGroupTable, "phaseStatusGroupPedClears", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 4, 1, 7, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseStatusGroupTable, "phaseStatusGroupWalks", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 4, 1, 8, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseStatusGroupTable, "phaseStatusGroupVehCalls", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 4, 1, 9, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseStatusGroupTable, "phaseStatusGroupPedCalls", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 4, 1, 10, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseStatusGroupTable, "phaseStatusGroupPhaseOns", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 4, 1, 11, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseStatusGroupTable, "phaseStatusGroupPhaseNexts", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 5, 1, 1, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_phaseControlGroupTable, "phaseControlGroupNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 5, 1, 2, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseControlGroupTable, "phaseControlGroupPhaseOmit", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 5, 1, 3, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseControlGroupTable, "phaseControlGroupPedOmit", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 5, 1, 4, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseControlGroupTable, "phaseControlGroupHold", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 5, 1, 5, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseControlGroupTable, "phaseControlGroupForceOff", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 5, 1, 6, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseControlGroupTable, "phaseControlGroupVehCall", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 1, 5, 1, 7, 0, 0}, {MAX_PHASEGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_phaseControlGroupTable, "phaseControlGroupPedCall", NULL},

    // detector - - NTCIP 1202
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_DETECTORS, OBJT_INT1, &hdlr_actionMax, "maxVehicleDetectors", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 1, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 2, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorOptions", &tVehDetOptions},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 4, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorCallPhase", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 5, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorSwitchPhase", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 6, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 2550, OBJT_INT2, &hdlr_vehicleDetectorTable, "vehicleDetectorDelay", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 7, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorExtend", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 8, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorQueueLimit", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 9, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorNoActivity", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 10, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorMaxPresence", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 11, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorErraticCounts", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 12, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorFailTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 13, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorAlarms", &tDetAlarm},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 14, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorReportedAlarms", &tVehDetReportedAlarm},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 15, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, 1, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorReset", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 16, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, (0x01 | 0x02), OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorOptions2", &tVehDetOptions2S},          // NEW IN OIDTABLE
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 17, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, MAX_DETECTORS, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorPairedDetector", NULL},                 // NEW IN OIDTABLE
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 18, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT16U_MAX, OBJT_INT2, &hdlr_vehicleDetectorTable, "vehicleDetectorPairedDetectorSpacing", NULL},             // NEW IN OIDTABLE
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 19, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 4000, OBJT_INT2, &hdlr_vehicleDetectorTable, "vehicleDetectorAvgVehicleLength", NULL},      // NEW IN OIDTABLE
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 20, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_vehicleDetectorTable, "vehicleDetectorLength", NULL},          // NEW IN OIDTABLE
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 2, 1, 21, 0, 0}, {MAX_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 4, OBJT_INT1, &hdlr_vehicleDetectorTable, "vehicleDetectorTravelMode", &tVehDetTravelMode}, // NEW IN OIDTABLE

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_DETGROUPS, OBJT_INT1, &hdlr_actionMax, "maxVehicleDetectorStatusGroups", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 4, 1, 1, 0, 0}, {MAX_DETGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorStatusGroupTable, "vehicleDetectorStatusGroupNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 4, 1, 2, 0, 0}, {MAX_DETGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorStatusGroupTable, "vehicleDetectorStatusGroupActive", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 4, 1, 3, 0, 0}, {MAX_DETGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorStatusGroupTable, "vehicleDetectorStatusGroupAlarms", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 5, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_volumeOccupancySequence, "volumeOccupancySequence", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 5, 2, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_volumeOccupancyPeriod, "volumeOccupancyPeriod", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 5, 3, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_activeVolumeOccupancyDetectors, "activeVolumeOccupancyDetectors", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 5, 4, 1, 1, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_volumeOccupancyTable, "detectorVolume", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 5, 4, 1, 2, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_volumeOccupancyTable, "detectorOccupancy", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 5, 4, 1, 3, 0}, {MAX_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 511, OBJT_INT2, &hdlr_volumeOccupancyTable, "detectorAvgSpeed", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 5, 5, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_RW, 0, INT16U_MAX, OBJT_INT2, &hdlr_volumeOccupancyPeriodV3, "volumeOccupancyPeriodV3", NULL}, // NEW IN OIDTABLE
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 5, 6, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_detectorSampleTime, "detectorSampleTime", NULL},                           // NEW IN OIDTABLE
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 5, 7, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_detectorSampleDuration, "detectorSampleDuration", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_PED_DETECTORS, OBJT_INT1, &hdlr_actionMax, "maxPedestrianDetectors", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 7, 1, 1, 0, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorTable, "pedestrianDetectorNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 7, 1, 2, 0, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorTable, "pedestrianDetectorCallPhase", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 7, 1, 3, 0, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorTable, "pedestrianDetectorNoActivity", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 7, 1, 4, 0, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorTable, "pedestrianDetectorMaxPresence", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 7, 1, 5, 0, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorTable, "pedestrianDetectorErraticCounts", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 7, 1, 6, 0, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorTable, "pedestrianDetectorAlarms", &tDetAlarm},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 7, 1, 7, 0, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, 1, OBJT_INT1, &hdlr_pedestrianDetectorTable, "pedestrianDetectorReset", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 7, 1, 8, 0, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorTable, "pedestrianButtonPushTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 7, 1, 9, 0, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorTable, "pedestrianDetectorOptions", &tPedDetOptionsStd},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 8, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_PEDGROUPS, OBJT_INT1, &hdlr_actionMax, "maxPedestrianDetectorGroups", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 9, 1, 1, 0, 0}, {MAX_PEDGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorStatusGroupTable, "pedestrianDetectorStatusGroupNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 9, 1, 2, 0, 0}, {MAX_PEDGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorStatusGroupTable, "pedestrianDetectorStatusGroupActive", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 9, 1, 3, 0, 0}, {MAX_PEDGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorStatusGroupTable, "pedestrianDetectorStatusGroupAlarms", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 10, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorSequence, "pedestrianDetectorSequence", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 10, 2, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_RW, 0, INT16U_MAX, OBJT_INT2, &hdlr_pedestrianDetectorPeriod, "pedestrianDetectorPeriod", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 10, 3, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_activePedestrianDetectors, "activePedestrianDetectors", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 10, 4, 1, 1, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianSampleTable, "pedestrianDetectorVolume", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 10, 4, 1, 2, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianSampleTable, "pedestrianDetectorActuations", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 10, 4, 1, 3, 0}, {MAX_PED_DETECTORS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianSampleTable, "pedestrianDetectorServices", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 10, 5, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_pedestrianDetectorSampleTime, "pedestrianDetectorSampleTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 10, 6, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_pedestrianDetectorSampleDuration, "pedestrianDetectorSampleDuration", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 11, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_DETECTORS / 8, OBJT_INT1, &hdlr_actionMax, "maxVehicleDetectorControlGroups", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 12, 1, 1, 0, 0}, {MAX_DETECTORS / 8, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorControlGroupTable, "vehicleDetectorControlGroupNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 12, 1, 2, 0, 0}, {MAX_DETECTORS / 8, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_vehicleDetectorControlGroupTable, "vehicleDetectorControlGroupActuation", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 13, 1, 1, 0, 0}, {MAX_PEDGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorControlGroupTable, "pedestrianDetectorControlGroupNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 2, 13, 1, 2, 0, 0}, {MAX_PEDGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_pedestrianDetectorControlGroupTable, "pedestrianDetectorControlGroupActuation", NULL},

    // Unit - - NTCIP 1202
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_unitStartUpFlash, "unitStartUpFlash", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 2, OBJT_INT1, &hdlr_unitAutoPedestrianClear, "unitAutoPedestrianClear", &tStatus1},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_unitBackupTime, "unitBackupTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_unitRedRevert, "unitRedRevert", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_unitControlStatus, "unitControlStatus", &tUnitCtlStatus},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_unitFlashStatus, "unitFlashStatus", &tUnitFlashStatus},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 7, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_unitAlarmStatus2, "unitAlarmStatus2", &tUnitAlarmStatus2},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 8, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_unitAlarmStatus1, "unitAlarmStatus1", &tUnitAlarmStatus1},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 9, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_shortAlarmStatus, "shortAlarmStatus", &tShortAlarmStatus},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 10, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_unitControl, "unitControl", &tUnitCtl},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 11, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_ALARMGROUPS, OBJT_INT1, &hdlr_actionMax, "maxAlarmGroups", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 12, 1, 1, 0, 0}, {MAX_ALARMGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_alarmGroupTable, "alarmGroupNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 12, 1, 2, 0, 0}, {MAX_ALARMGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_alarmGroupTable, "alarmGroupState", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 13, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_SPECIALFUNCS, OBJT_INT1, &hdlr_actionMax, "maxSpecialFunctionOutputs", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 14, 1, 1, 0, 0}, {MAX_SPECIALFUNCS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_specialFunctionOutputTable, "specialFunctionOutputNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 14, 1, 3, 0, 0}, {MAX_SPECIALFUNCS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, 1, OBJT_INT1, &hdlr_specialFunctionOutputTable, "specialFunctionOutputControl", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 14, 1, 4, 0, 0}, {MAX_SPECIALFUNCS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 1, OBJT_INT1, &hdlr_specialFunctionOutputTable, "specialFunctionOutputStatus", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 15, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_unitMCETimeout, "unitMCETimeout", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 16, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, 1, OBJT_INT1, &hdlr_unitMCEIntAdv, "unitMCEIntAdv", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 18, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_unitStartupFlashMode, "unitStartupFlashMode", &tUnitStartUpFlashMode},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 19, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, 16777216, OBJT_INT4, &hdlr_unitUserDefinedBackupTime, "unitUserDefinedBackupTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 3, 26, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_unitAlarmStatus4, "unitAlarmStatus4", &tUnitAlarmStatus4},

    // Coord - NTCIP 1202
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_coordOperationalMode, "coordOperationalMode", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 2, 5, OBJT_INT1, &hdlr_coordCorrectionMode, "coordCorrectionMode", &tCoordCorrMode},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 2, 4, OBJT_INT1, &hdlr_coordMaximumMode, "coordMaximumMode", &tCoordMaxMode},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 2, 3, OBJT_INT1, &hdlr_coordForceMode, "coordForceMode", &tCoordForceMode},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_PATTERNS, OBJT_INT1, &hdlr_actionMax, "maxPatterns", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 6, 0, 0, 0, 0}, {/*patterns*/ 0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 2, OBJT_INT1, &hdlr_actionMax, "patternTableType", &tPatTableType}, // pattern table type is always 2 for patterns, so use max function
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 7, 1, 1, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_patternTable, "patternNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 7, 1, 2, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_patternTable, "patternCycleTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 7, 1, 3, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_patternTable, "patternOffsetTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 7, 1, 4, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, MAX_SPLITS, OBJT_INT1, &hdlr_table_patternTable, "patternSplitNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 7, 1, 5, 0, 0}, {MAX_PATTERNS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, MAX_SEQUENCES, OBJT_INT1, &hdlr_table_patternTable, "patternSequenceNumber", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 8, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_SPLITS, OBJT_INT1, &hdlr_actionMax, "maxSplits", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 9, 1, 1, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_splitTable, "splitNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 9, 1, 2, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_splitTable, "splitPhase", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 9, 1, 3, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_splitTable, "splitTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 9, 1, 4, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 2, 8, OBJT_INT1, &hdlr_table_splitTable, "splitMode", &tSplitMode},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 9, 1, 5, 0, 0}, {MAX_SPLITS, MAX_PHASES, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_table_splitTable, "splitCoordPhase", &tStatus0},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 10, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_coordPatternStatus, "coordPatternStatus", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 11, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_localFreeStatus, "localFreeStatus", &tLocalFreeStatus},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 12, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 510, OBJT_INT2, &hdlr_coordCycleStatus, "coordCycleStatus", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 13, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 510, OBJT_INT2, &hdlr_coordSyncStatus, "coordSyncStatus", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 14, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_systemPatternControl, "systemPatternControl", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 15, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_systemSyncControl, "systemSyncControl", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 4, 16, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 1, 7, OBJT_INT1, &hdlr_unitCoordSyncPoint, "unitCoordSyncPoint", &tUnitCoordSyncPoint},

    // timebaseAsc - - NTCIP 1202
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 5, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_timebaseAscPatternSync, "timebaseAscPatternSync", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 5, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_TBC_ACTIONS, OBJT_INT1, &hdlr_actionMax, "maxTimebaseAscActions", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 5, 3, 1, 1, 0, 0}, {MAX_TBC_ACTIONS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_timebaseAscActionTable, "timebaseAscActionNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 5, 3, 1, 2, 0, 0}, {MAX_TBC_ACTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_timebaseAscActionTable, "timebaseAscPattern", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 5, 3, 1, 3, 0, 0}, {MAX_TBC_ACTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_timebaseAscActionTable, "timebaseAscAuxillaryFunction", &tTbAuxFunction},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 5, 3, 1, 4, 0, 0}, {MAX_TBC_ACTIONS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_timebaseAscActionTable, "timebaseAscSpecialFunction", &tTBSpecialFunction},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 5, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_timebaseAscActionStatus, "timebaseAscActionStatus", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 5, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, INT8U_MAX, OBJT_INT1, &hdlr_actionPlanControl, "actionPlanControl", NULL},

    // preempt - - NTCIP 1202
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_PREEMPTS, OBJT_INT1, &hdlr_actionMax, "maxPreempts", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 1, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_preemptTable, "preemptNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 2, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 63, OBJT_INT1, &hdlr_preemptTable, "preemptControl", &tPreemptCtl}, // (bits 4-7 are reserved)
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 3, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_PREEMPTS, OBJT_INT1, &hdlr_preemptTable, "preemptLink", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 4, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 600, OBJT_INT2, &hdlr_preemptTable, "preemptDelay", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 5, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_preemptTable, "preemptMinimumDuration", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 6, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_preemptTable, "preemptMinimumGreen", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 7, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_preemptTable, "preemptMinimumWalk", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 8, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_preemptTable, "preemptEnterPedClear", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 9, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_preemptTable, "preemptTrackGreen", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 10, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_preemptTable, "preemptDwellGreen", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 11, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_preemptTable, "preemptMaximumPresence", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 12, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PHASES, OBJT_OCTET, &hdlr_preemptTable, "preemptTrackPhase", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 13, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PHASES, OBJT_OCTET, &hdlr_preemptTable, "preemptDwellPhase", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 14, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PHASES, OBJT_OCTET, &hdlr_preemptTable, "preemptDwellPed", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 15, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PHASES, OBJT_OCTET, &hdlr_preemptTable, "preemptExitPhase", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 16, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 10, OBJT_INT1, &hdlr_preemptTable, "preemptState", &tPreemptState},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 17, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_VEH_OVERLAPS, OBJT_OCTET, &hdlr_preemptTable, "preemptTrackOverlap", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 18, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_VEH_OVERLAPS, OBJT_OCTET, &hdlr_preemptTable, "preemptDwellOverlap", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 19, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PHASES, OBJT_OCTET, &hdlr_preemptTable, "preemptCyclingPhase", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 20, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PHASES, OBJT_OCTET, &hdlr_preemptTable, "preemptCyclingPed", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 21, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_VEH_OVERLAPS, OBJT_OCTET, &hdlr_preemptTable, "preemptCyclingOverlap", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 22, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_preemptTable, "preemptEnterYellowChange", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 23, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_preemptTable, "preemptEnterRedClear", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 24, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_preemptTable, "preemptTrackYellowChange", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 25, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_preemptTable, "preemptTrackRedClear", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 26, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, MAX_SEQUENCES, OBJT_INT1, &hdlr_preemptTable, "preemptSequenceNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 2, 1, 27, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_preemptTable, "preemptExitType", &tPreemptExitType},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 3, 1, 1, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_preemptControlTable, "preemptControlNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 3, 1, 2, 0, 0}, {MAX_PREEMPTS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 0, 1, OBJT_INT1, &hdlr_table_preemptControlTable, "preemptControlState", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_PREEMPTS, OBJT_INT1, &hdlr_preemptStatus, "preemptStatus", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, MAX_PREEMPT_GROUPS, OBJT_INT1, &hdlr_actionMax, "maxPreemptGroups", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 6, 1, 1, 0, 0}, {MAX_PREEMPT_GROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_preemptStatusGroupTable, "preemptStatusGroupNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 6, 6, 1, 2, 0, 0}, {MAX_PREEMPT_GROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_preemptStatusGroupTable, "preemptStatusGroup", NULL},

    // ring - - NTCIP 1202
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_RINGS, OBJT_INT1, &hdlr_actionMax, "maxRings", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_SEQUENCES, OBJT_INT1, &hdlr_actionMax, "maxSequences", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 3, 1, 1, 0, 0}, {MAX_SEQUENCES, MAX_RINGS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_sequenceTable, "sequenceNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 3, 1, 2, 0, 0}, {MAX_SEQUENCES, MAX_RINGS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_sequenceTable, "sequenceRingNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 3, 1, 3, 0, 0}, {MAX_SEQUENCES, MAX_RINGS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, RING_SEQUENCE_SIZE, OBJT_OCTET, &hdlr_table_sequenceTable, "sequenceData", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_RINGGROUPS, OBJT_INT1, &hdlr_actionMax, "maxRingControlGroups", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 5, 1, 1, 0, 0}, {MAX_RINGGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_ringControlGroupTable, "ringControlGroupNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 5, 1, 2, 0, 0}, {MAX_RINGGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 1, (1 << MAX_RINGS) - 1, OBJT_INT1, &hdlr_table_ringControlGroupTable, "ringControlGroupStopTime", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 5, 1, 3, 0, 0}, {MAX_RINGGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 1, (1 << MAX_RINGS) - 1, OBJT_INT1, &hdlr_table_ringControlGroupTable, "ringControlGroupForceOff", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 5, 1, 4, 0, 0}, {MAX_RINGGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 1, (1 << MAX_RINGS) - 1, OBJT_INT1, &hdlr_table_ringControlGroupTable, "ringControlGroupMax2", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 5, 1, 5, 0, 0}, {MAX_RINGGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 1, (1 << MAX_RINGS) - 1, OBJT_INT1, &hdlr_table_ringControlGroupTable, "ringControlGroupMaxInhibit", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 5, 1, 6, 0, 0}, {MAX_RINGGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 1, (1 << MAX_RINGS) - 1, OBJT_INT1, &hdlr_table_ringControlGroupTable, "ringControlGroupPedRecycle", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 5, 1, 7, 0, 0}, {MAX_RINGGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 1, (1 << MAX_RINGS) - 1, OBJT_INT1, &hdlr_table_ringControlGroupTable, "ringControlGroupRedRest", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 5, 1, 8, 0, 0}, {MAX_RINGGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 1, (1 << MAX_RINGS) - 1, OBJT_INT1, &hdlr_table_ringControlGroupTable, "ringControlGroupOmitRedClear", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 5, 1, 9, 0, 0}, {MAX_RINGGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RW | AF_BU, 1, (1 << MAX_RINGS) - 1, OBJT_INT1, &hdlr_table_ringControlGroupTable, "ringControlGroupMax3", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 7, 6, 1, 1, 0, 0}, {MAX_RINGS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_ringStatus, "ringStatus", &tRingStatus}, // Details in this oid

    // channel -- NTCIP 1202
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 8, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_CHANNELS, OBJT_INT1, &hdlr_actionMax, "maxChannels", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 8, 2, 1, 1, 0, 0}, {MAX_CHANNELS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_channelTable, "channelNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 8, 2, 1, 2, 0, 0}, {MAX_CHANNELS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_channelTable, "channelControlSource", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 8, 2, 1, 3, 0, 0}, {MAX_CHANNELS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 2, 5, OBJT_INT1, &hdlr_table_channelTable, "channelControlType", &tChannelCtlType},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 8, 2, 1, 4, 0, 0}, {MAX_CHANNELS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_channelTable, "channelFlash", NULL}, // (bits 0 and 4-7 are reserved)
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 8, 2, 1, 5, 0, 0}, {MAX_CHANNELS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_channelTable, "channelDim", NULL},   // (bits 4-7 are reserved)

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 8, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_CHANGROUPS, OBJT_INT1, &hdlr_actionMax, "maxChannelStatusGroups", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 8, 4, 1, 1, 0, 0}, {MAX_CHANGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_table_channelStatusGroupTable, "channelStatusGroupNumber"},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 8, 4, 1, 2, 0, 0}, {MAX_CHANGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_channelStatusGroupTable, "channelStatusGroupReds", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 8, 4, 1, 3, 0, 0}, {MAX_CHANGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_channelStatusGroupTable, "channelStatusGroupYellows", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 8, 4, 1, 4, 0, 0}, {MAX_CHANGROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_table_channelStatusGroupTable, "channelStatusGroupGreens", NULL},

    // overlap - - NTCIP 1202
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_VEH_OVERLAPS, OBJT_INT1, &hdlr_actionMax, "maxOverlaps", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 2, 1, 1, 0, 0}, {MAX_VEH_OVERLAPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_overTable, "overlapNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 2, 1, 2, 0, 0}, {MAX_VEH_OVERLAPS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 2, 6, OBJT_INT1, &hdlr_overTable, "overlapType", &tOverlapType}, // 1202v2.19 had type as S, but should have been P2 so we fixed it  //xxxx was type P in 1202v0213
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 2, 1, 3, 0, 0}, {MAX_VEH_OVERLAPS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PHASES, OBJT_OCTET, &hdlr_overTable, "overlapIncludedPhases", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 2, 1, 4, 0, 0}, {MAX_VEH_OVERLAPS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P2, 0, MAX_PHASES, OBJT_OCTET, &hdlr_overTable, "overlapModifierPhases", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 2, 1, 5, 0, 0}, {MAX_VEH_OVERLAPS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_overTable, "overlapTrailGreen", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 2, 1, 6, 0, 0}, {MAX_VEH_OVERLAPS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_overTable, "overlapTrailYellow", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 2, 1, 7, 0, 0}, {MAX_VEH_OVERLAPS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_overTable, "overlapTrailRed", NULL},

    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_OVERLAP_GROUPS, OBJT_INT1, &hdlr_actionMax, "maxOverlapStatusGroups", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 4, 1, 1, 0, 0}, {MAX_OVERLAP_GROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_overlapStatusGroupTable, "overlapStatusGroupNumber", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 4, 1, 2, 0, 0}, {MAX_OVERLAP_GROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_overlapStatusGroupTable, "overlapStatusGroupReds", NULL},    // MB_OVERLAPGROUP(MB_STAT, overlapStatusGroupReds)
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 4, 1, 3, 0, 0}, {MAX_OVERLAP_GROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_overlapStatusGroupTable, "overlapStatusGroupYellows", NULL}, // MB_OVERLAPGROUP(MB_STAT, overlapStatusGroupYellows)
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 9, 4, 1, 4, 0, 0}, {MAX_OVERLAP_GROUPS, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_overlapStatusGroupTable, "overlapStatusGroupGreens", NULL},  // MB_OVERLAPGROUP(MB_STAT, overlapStatusGroupGreens)

    // ts2port1 - NTCIP 1202
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 10, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_PORT1_DEVICES, OBJT_INT1, &hdlr_actionMax, "maxPort1Addresses", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 10, 2, 1, 1, 0, 0}, {MAX_PORT1_DEVICES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_port1Table, "port1Number", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 10, 2, 1, 2, 0, 0}, {MAX_PORT1_DEVICES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 2, OBJT_INT1, &hdlr_port1Table, "port1DevicePresent", &tStatus0},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 10, 2, 1, 3, 0, 0}, {MAX_PORT1_DEVICES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_port1Table, "port1Frame40Enable", &tStatus0},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 10, 2, 1, 4, 0, 0}, {MAX_PORT1_DEVICES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_port1Table, "port1Status", &tPort1Status},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 10, 2, 1, 5, 0, 0}, {MAX_PORT1_DEVICES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_port1Table, "port1FaultFrame", NULL},

    // ascBlock - NTCIP 1202
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 11, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 2, MA_SIZE_ASCBLKGETCTRL, OBJT_OCTET, &hdlr_ascBlockGetControl, "ascBlockGetControl", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 11, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 2, SIZE_ASCBLOCKDATA, OBJT_OCTET, &hdlr_ascBlockData, "ascBlockData", NULL},
    {NTCIP_1202, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 1, 11, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_ascBlockErrorStatus, "ascBlockErrorStatus", NULL},

    // *********************************************************************RAMPMETER*********************************************************************************************************

    // RMC GENERAL CONFIGURATION NODE
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 1, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcCommRefreshThreshold, "rmcCommRefreshThreshold", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 1, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_P, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcCalcInterval, "rmcCalcInterval", NULL},

    // // MAINLINE LANE CONFIGURATION, CONTROL AND STATUS NODE
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_P, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcAveragingPeriods, "rmcAveragingPeriods", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_MAINLINE_LANES, OBJT_INT1, &hdlr_actionMax, "rmcMaxNumML", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_MAINLINE_LANES, OBJT_INT1, &hdlr_actionMax, "rmcNumML", NULL},

    // // Mainline Lane Configuration and Control Table -- Begin
    //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcMainline Lane Configuration and Control Table"},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 1, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_MAINLINE_LANES, OBJT_INT1, &hdlr_rmcMLCtrlTable, "rmcMLNumber", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 2, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 5, OBJT_INT1, &hdlr_rmcMLCtrlTable, "rmcMLMode", &tMLMode},
    //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 3, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMLCtrlTable, "rmcMLLeadZoneLength", NULL},  // <-- DEPRECATED
    //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 4, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMLCtrlTable, "rmcMLTrailZoneLength", NULL}, // <-- DEPRECATED
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 5, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 9, OBJT_INT1, &hdlr_rmcMLCtrlTable, "rmcMLUsageMode", &tMLUsageMode},
    //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 6, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMLCtrlTable, "rmcSpeedTrapSpacing", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 7, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMLCtrlTable, "rmcMLErraticCount", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 8, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMLCtrlTable, "rmcMLMaxPresence", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 9, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMLCtrlTable, "rmcMLNoActivity", NULL},
    //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 10, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMLCtrlTable, "rmcVehicleLength", NULL}, // <-- DEPRECATED
    // ADDED in V2
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 11, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMLCtrlTable, "rmcMLLeadZoneLengthV2", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 12, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMLCtrlTable, "rmcMLTrailZoneLengthV2", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 13, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMLCtrlTable, "rmcSpeedTrapSpacingV2", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 4, 1, 14, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMLCtrlTable, "rmcVehicleLengthV2", NULL},

    // // Mainline Lane Configuration and Control Table -- End

    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcAverageFlowRate, "rmcAverageFlowRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcAverageOccupancy, "rmcAverageOccupancy", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 7, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcAverageSpeed, "rmcAverageSpeed", NULL},

    // // Mainline Lane Status Table -- Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 8, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcMainline Lane Status Table", NULL},
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 8, 1, 1, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 8, OBJT_INT1, &hdlr_rmcMLStatTable, "rmcMLLeadStatus", &tMLTLStatus},
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 8, 1, 2, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 8, OBJT_INT1, &hdlr_rmcMLStatTable, "rmcMLTrailStatus", &tMLtLStatus},
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 8, 1, 3, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 4, OBJT_INT1, &hdlr_rmcMLStatTable, "rmcMLStatus", &tMLStatus},
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 8, 1, 4, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 8, OBJT_INT1, &hdlr_rmcMLStatTable, "rmcMLUsageStatus", &tMLUsageMode},
    // // ADDED in V2
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 8, 1, 5, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT16U_MAX, OBJT_INT2, &hdlr_rmcMLStatTable, "rmcMLHistLeadStatus", &tMLHistTLStatus},  // <-- BITMAP 16
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 8, 1, 6, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT16U_MAX, OBJT_INT2, &hdlr_rmcMLStatTable, "rmcMLHistTrailStatus", &tMLHistTLStatus}, // <-- BITMAP 16
    // // Mainline Lane Status Table -- End

    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 9, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMaxNumFlowNoActivityTableEntries, "rmcMaxNumFlowNoActivityTableEntries", NULL}, // <-- BITMAP 16 // Has right direction
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 10, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcNumFlowNoActivityTableEntries, "rmcNumFlowNoActivityTableEntries", NULL}, // Has right direction

    // Flow Based No Activity Table -- Begin
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 11, 1, 1, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMLFlowBasedNoActivityTable, "rmcMLFlowBasedNoActivityIndex", NULL},    // Has right direction
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 11, 1, 2, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT16U_MAX, OBJT_INT1, &hdlr_rmcMLFlowBasedNoActivityTable, "rmcFlowBasedNoActivityThreshold", NULL}, // Has right direction
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 11, 1, 3, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT16U_MAX, OBJT_INT1, &hdlr_rmcMLFlowBasedNoActivityTable, "rmcFlowBasedNoActivityInterval", NULL},  // Has right direction

    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 12, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcNumFlowRateLanes, "rmcNumFlowRateLanes", NULL},
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 13, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcNumAverageOccupancyLanes, "rmcNumAverageOccupancyLanes", NULL},
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 14, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcNumAverageSpeedLanes, "rmcNumAverageSpeedLanes", NULL},
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 2, 15, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcFlowBasedNoActivityDuration, "rmcFlowBasedNoActivityDuration", NULL},

    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT32U_MAX, OBJT_INT1, &hdlr_rmcMaxNumMeteredLanes, "rmcMaxNumMeteredLanes", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 2, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT32U_MAX, OBJT_INT1, &hdlr_rmcNumMeteredLanes, "rmcNumMeteredLanes", NULL},

    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT32U_MAX, OBJT_INT1, &hdlr_rmcHistDetectorReset, "rmcHistDetectorReset", NULL},

    // // Metered Lane Configuration Table -- Begin
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 1, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcMeterNumber", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 2, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcDependGroupNumber", NULL}, // MAX_METERING_LANES snmpv2
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 3, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcDependGroupSeqNumber", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 4, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 6, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcCmdSourcePriorityOrder", &tCmdSourcePriOrder},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 5, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcDemandErraticCount", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 6, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcDemandMaxPresence", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 7, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcDemandNoActivity", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 8, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcMinMeterTime", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 9, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcMinNonMeterTime", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 10, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcAbsoluteMinMeterRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 11, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcAbsoluteMaxMeterRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 12, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcSystemMinMeterRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 13, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcSystemMaxMeterRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 14, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcStartAlert", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 15, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcStartWarning", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 16, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcStartGreen", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 17, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcStartGapTime", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 18, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcStartGapQueueDetectorNum", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 19, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcStartYellow", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 20, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcStartRed", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 21, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcMinRed", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 22, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcRedViolationClearance", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 23, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcRedViolationAdjust", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 24, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcMinGreen", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 25, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcMaxGreen", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 26, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcYellow", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 27, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcShortStopTime", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 28, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcShortStopOccupancy", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 29, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcShortStopQueueDetectorNum", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 30, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcLongStopTime", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 31, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcDemandGap", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 32, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcDemandRed", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 33, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcShutNormalRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 34, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcShutWarning", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 35, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcShutTime", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 36, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcPostMeterGreen", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 37, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcQueueViolationFlag", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 38, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcQueueShutdownFlag", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 39, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcQueueAdjustUsage", &tQueueAdjUsage},
    // ADDED in V2
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 40, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCfgTable, "rmcDemandDependMaxPresence", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 3, 1, 41, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCfgTable, "rmcDemandDependNoActivity", NULL},
    // // Metered Lane Configuration Table -- End

    // // Metered Lane Control Table -- Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_P, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcMetered Lane Control Table", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 1, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcMeterMode", &tStatus0},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 2, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 6, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcManualAction", &tAction},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 3, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcManualPlan", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 4, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCtrlTable, "rmcManualRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 5, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcManualVehiclesPerGrn", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 6, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 6, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcIntercoAction", &tAction},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 7, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcIntercoPlan", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 8, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCtrlTable, "rmcIntercoRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 9, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcIntercoVehiclesPerGrn", NULL},

    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 10, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 6, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcCommActionMode", &tAction}, // V2 Name
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 11, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcCommPlan", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 12, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCtrlTable, "rmcCommRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 13, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcCommVehiclesPerGrn", NULL},

    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 14, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 5, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcDefaultAction", &tAction},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 15, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcDefaultPlan", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 16, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCtrlTable, "rmcDefaultRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 17, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcDefaultVehiclesPerGrn", NULL},

    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 18, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcDemandMode", &tDemandMode},
    // // ADDED in V2
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 19, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, 3, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcPreMeterNonGreen", &tPreMeterNonGreen},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 20, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCtrlTable, "rmcCritFlowRateThresh", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 21, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterCtrlTable, "rmcCritOccupancyThresh", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 7, 1, 22, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterCtrlTable, "rmcCriticalSpeedThreshold", NULL},

    // // Metered Lane Control Table -- End

    // // Metered Lane Status Table -- Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcMetered Lane Status Table", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 1, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 5, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcRequestedCommandSource", &tCmdSource},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 2, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 5, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcImplementCommandSource", &tCmdSource},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 3, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 8, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcImplementAction", &tImplAction},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 4, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcImplementPlan", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 5, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterStatTable, "rmcImplementRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 6, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcImplementVehiclesPerGrn", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 7, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 5, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcRequestAction", &tAction},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 8, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcRequestPlan", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 9, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterStatTable, "rmcRequestRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 10, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcRequestVehiclesPerGrn", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 11, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 7, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcCommAction", &tAction},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 12, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterStatTable, "rmcBaseMeterRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 13, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterStatTable, "rmcActiveMeterRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 14, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 6, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcTBActionStatus", &tAction},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 15, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcTBPlanStatus", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 16, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterStatTable, "rmcTBRateStatus", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 17, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcTBVehiclesPerGrnStatus", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 18, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 0, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcActiveInterval", &tInterval},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 19, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterStatTable, "rmcTBCMinMeterRateStatus", NULL}, // <-- DEPRECATED
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 20, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterStatTable, "rmcTBCMaxMeterRateStatus", NULL}, // <-- DEPRECATED
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 21, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterStatTable, "rmcOperMinMeterRateStatus", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 22, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterStatTable, "rmcOperMaxMeterRateStatus", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 23, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 9, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcDemandStatus", &tDemandStatus},
    // ADDED in V2
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 24, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterStatTable, "rmcHistDemandStatus", &tHistDemandStatus}, // <-- BITMAP 16
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 25, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcCycleCount", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 26, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterStatTable, "rmcTBCMinMeterRateStatusV2", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 27, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterStatTable, "rmcTBCMaxMeterRateStatusV2", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 28, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 3, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcCumulQueAdjStat", &tCumulQueAdjStat},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 1, 8, 1, 29, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 1, OBJT_INT1, &hdlr_rmcMeterStatTable, "rmcMainQueueFlag", NULL},
    // // Metered Lane Status Table -- End

    // //{NTCIP_1207, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcMetered Lane Dependency Group Configuration, Control and Status node", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMaxNumDependGroups, "rmcMaxNumDependGroups", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 2, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcNumDependGroups, "rmcNumDependGroups", NULL},

    // // Dependency Group Configuration and Control Table -- Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_P, 0x0, INT8U_MAX, OBJT_INT1, &hdlr_, "rmcDependency Group Configuration and Control Table", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 1, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcDependGroupMode", &tStatus0},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 2, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, 3, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcSignalServiceMode", &tServiceMode}, // MIN AND MAX VALUES ARE 1 TO 4
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 3, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcShutGapTime", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 4, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcShutGapReductTime", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 5, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcShutGapReductValue", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 6, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcGreenOffset", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 7, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcMinFractionalOffset", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 8, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcPriorityLaneNum", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 9, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcPriorityLaneRedDelay", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 10, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcMergeMode", &tStatus0},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 11, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcMergeGap", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 12, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcMergeDelay", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 13, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcQueueMergeFlag", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 14, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcMergeErraticCount", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 15, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcDependGroupCtrlTable, "rmcMergeMaxPresence", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 16, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcDependGroupCtrlTable, "rmcMergeNoActivity", NULL},
    // // ADDED in V2
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 3, 1, 17, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependGroupCtrlTable, "rmcMinMutexRed", NULL},
    // // Dependency Group Configuration and Control Table -- End

    // // Dependency Group Status Table - Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 4, 1, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0, MAX, OBJT_INT1, &hdlr_, "rmcDependency Group Status Table", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 4, 1, 1, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 1, OBJT_INT1, &hdlr_rmcDependGroupStatTable, "rmcMergeFlag", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 4, 1, 2, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 7, OBJT_INT1, &hdlr_rmcDependGroupStatTable, "rmcMergeStatus", &tMLTLStatus},
    // ADDED in V2
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 4, 1, 3, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcDependGroupStatTable, "rmcHistMergeStatus", &tHistMergeStatus}, // <-- BITMAP 16
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 2, 4, 1, 4, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 1, OBJT_INT1, &hdlr_rmcDependGroupStatTable, "rmcMergeOverStat", NULL},
    // // Dependency Group Status Table - End

    // //{NTCIP_1207, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcQueue Detector Configuration, Control and Status node", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_QUEUES, OBJT_INT1, &hdlr_actionMax, "rmcMaxNumQueueEntries", NULL}, // SHOULD BE 12 NOT 10
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 2, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_QUEUES, OBJT_INT1, &hdlr_actionMax, "rmcNumQueueEntries", NULL},

    // // Queue Detector Configuration and Control Table -- Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1,0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_P, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcQueue Detector Configuration and Control Table", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 1, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_QUEUES, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueNum", NULL}, // CHANGE
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 2, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 3, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueType", &tQueueType},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 3, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueDetectMode", &tQueueDetectMode},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 4, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueLengthUpLimit", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 5, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueLengthLowLimit", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 6, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueCtrlTable, "rmcQueueOccUpLimit", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 7, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueOccUpDelay", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 8, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueCtrlTable, "rmcQueueOccLowLimit", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 9, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueOccLowDelay", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 10, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueCtrlTable, "rmcQueueQOccUpLimit", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 11, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueCtrlTable, "rmcQueueQOccUpDelay", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 12, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueCtrlTable, "rmcQueueQOccLowLimit", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 13, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueCtrlTable, "rmcQueueQOccLowDelay", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 14, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 4, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueAdjustMode", &tQueueAdjMode},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 15, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueCtrlTable, "rmcQueueAdjustRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 16, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueCtrlTable, "rmcQueueAdjustRateLimit", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 17, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueAdjustRateDelay", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 18, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueAdjustRateIter", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 19, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueAdjustLevel", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 20, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueAdjustLevelLimit", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 21, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueAdjustLevelDelay", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 22, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueAdjustLevelIter", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 23, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueCtrlTable, "rmcQueueReplaceRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 24, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueDetectorErraticCount", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 25, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueCtrlTable, "rmcQueueMaxPresence", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 26, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueCtrlTable, "rmcQueueNoActivity", NULL},
    // ADDED in V2
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 27, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueCtrlTable, "rmcQueueDependMaxPresence", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 1, 28, 0}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueCtrlTable, "rmcQueueDependNoActivity", NULL},
    // Queue Detector Configuration and Control Table -- End

    // Queue Detector Status Table -- Begin
    //{NTCIP_1207, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_NONE, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcQueue Detector Status Table", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 10, 1, 1}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 1, OBJT_INT1, &hdlr_rmcQueueStatTable, "rmcQueueFlag", NULL}, // The code needs to change
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 10, 1, 2}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 9, OBJT_INT1, &hdlr_rmcQueueStatTable, "rmcQueueStatus", &tDemandStatus},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 3, 3, 10, 1, 3}, {MAX_QUEUES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT16U_MAX, OBJT_INT2, &hdlr_rmcQueueStatTable, "rmcHistQueueStatus", &tHistDemandStatus}, // <-- BITMAP16
    // // Queue Detector Status Table -- End

    // //{NTCIP_1207, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcMetered Lane Passage Detector Configuration, Control and Status node", NULL},

    // // Passage Detector Configuration and Control Table -- Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 5, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_P, 0x1, 0x3, OBJT_INT1, &hdlr_, "rmcPassage Detector Configuration and Control Table", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 5, 1, 1, 1, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcPassageCtrlTable, "rmcPassageMode", &tPassageMode},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 5, 1, 1, 2, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcPassageCtrlTable, "rmcPassageErraticCount", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 5, 1, 1, 3, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcPassageCtrlTable, "rmcPassageMaxPresence", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 5, 1, 1, 4, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcPassageCtrlTable, "rmcPassageNoActivity", NULL},
    // ADDED in V2
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 5, 1, 1, 5, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcPassageCtrlTable, "rmcPassageDependNoActivity", NULL},
    // // Passage Detector Configuration and Control Table -- End

    // // Passage Detector Status Table -- Begin
    // //{NTCIP_1207, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcPassage Detector Status Table", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 5, 2, 1, 1, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, 8, OBJT_INT1, &hdlr_rmcPassageStatTable, "rmcPassageStatus", &tDemandStatus},
    // // ADDED in V2
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 5, 2, 1, 2, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT16U_MAX, OBJT_INT2, &hdlr_rmcPassageStatTable, "rmcHistPassageStatus", &tHistDemandStatus}, // <-- BITMAP16
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 5, 2, 1, 3, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcPassageStatTable, "rmcPassageVehicleCount", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 3, 5, 2, 1, 4, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcPassageStatTable, "rmcRedViolationCount", NULL},
    // // Passage Detector Status Table --

    // //{NTCIP_1207, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcMETERING PLAN NODE", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 4, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMaxNumMeteringPlans, "rmcMaxNumMeteringPlans", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 4, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcNumMeteringPlans, "rmcNumMeteringPlans", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 4, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMaxNumLevelsPerPlan, "rmcMaxNumLevelsPerPlan", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 4, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcNumMeteringLevels, "rmcNumMeteringLevels", NULL},

    // // Metering Plan Table - Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 4, 5, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcMetering Plan Table", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 4, 5, 1, 1, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeteringPlanTable, "rmcMeteringPlanNumber", NULL}, // CHECK IT AGAIN
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 4, 5, 1, 2, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeteringPlanTable, "rmcMeteringLevel", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 4, 5, 1, 3, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeteringPlanTable, "rmcMeteringRate", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 4, 5, 1, 4, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeteringPlanTable, "rmcFlowRateThreshold", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 4, 5, 1, 5, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeteringPlanTable, "rmcOccupancyThreshold", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 4, 5, 1, 6, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeteringPlanTable, "rmcSpeedThreshold", NULL},
    // // Metering Plan Table -- End

    // //{NTCIP_1207, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcSCHEDULING ACTION OBJECTS", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMaxNumTBCActions, "rmcMaxNumTBCActions", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcNumTBCActions, "rmcNumTBCActions", NULL},

    // // Timebase Control Action Table -- Begin
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 3, 1, 1, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcActionTable, "rmcActionNumber", NULL},  // Needs review: MAXIMUM Value base on rmcMaxNumTBCActions
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 3, 1, 2, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_rmcActionTable, "rmcActionMode", NULL},             // Needs review: MAXIMUM Value base on rmcMaxNumTBCActions
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 3, 1, 3, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcActionTable, "rmcMeterActionNum", NULL}, // Needs review: MAXIMUM Value base on rmcMaxNumTBCActions
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 3, 1, 4, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcActionTable, "rmcMLActionNum", NULL},    // Needs review: MAXIMUM Value base on rmcMaxNumTBCActions
    // // Timebase Control Action Table -- End

    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMaxNumMeterTBCActions, "rmcMaxNumMeterTBCActions", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterTBCActions, "rmcMeterTBCActions", NULL},

    // // Metered Lane Timebase Control Action Table -- Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 6, 1, 0, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcMetered Lane Timebase Control Action Table", NULL}, //Needs review: MAXIMUM Value base on rmcMaxNumMeterTBCActions
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 6, 1, 1, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterActionTable, "rmcMeterActionIndex", NULL}, //Needs review: MAXIMUM Value base on rmcMaxNumMeterTBCActions
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 6, 1, 2, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_rmcMeterActionTable, "rmcMeterActionMode", NULL}, //Needs review: MAXIMUM Value base on rmcMaxNumMeterTBCActions
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 6, 1, 3, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 6, OBJT_INT1, &hdlr_rmcMeterActionTable, "rmcTBActionCtrl", &tAction}, //Needs review: MAXIMUM Value base on rmcMaxNumMeterTBCActions
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 6, 1, 4, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterActionTable, "rmcTBPlanCtrl", NULL}, //Needs review: MAXIMUM Value base on rmcMaxNumMeterTBCActions
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 6, 1, 5, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterActionTable, "rmcTB Rate Ctrl", NULL}, //Needs review: MAXIMUM Value base on rmcMaxNumMeterTBCActions
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 6, 1, 6, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterActionTable, "rmcTBVehiclesPerGrnCtrl", NULL}, //Needs review: MAXIMUM Value base on rmcMaxNumMeterTBCActions
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 6, 1, 7, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterActionTable, "rmcTBCMinMeterRateCtrl", NULL}, //Needs review: MAXIMUM Value base on rmcMaxNumMeterTBCActions
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 6, 1, 8, 0, 0}, {MAX_SPEED_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_rmcMeterActionTable, "rmcTBCMaxMeterRateCtrl", NULL}, //Needs review: MAXIMUM Value base on rmcMaxNumMeterTBCActions
    // Metered Lane Timebase Control Action Table -- End

    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 7, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMaxNumMLTBCActions, "rmcMaxNumMLTBCActions", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 8, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcNumMLTBCActions, "rmcNumMLTBCActions", NULL},

    // // Mainline Timebase Control Action Table - Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 9, 1, 0, 0, 0}, {MAX_FLOWRATE_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcMainline Timebase Control Action Table", NULL}, //Needs review: MAXIMUM Value base on rmcMaxNumMLTBCActions
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 9, 1, 1, 0, 0}, {MAX_FLOWRATE_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_rmcMLActionTable, "rmcMLActionIndex", NULL}, //Needs review: MAXIMUM Value base on rmcMaxNumMLTBCActions
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 9, 1, 2, 0, 0}, {MAX_FLOWRATE_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 0, 1, OBJT_INT1, &hdlr_rmcMLActionTable, "rmcMLActionMode", NULL}, //Needs review: MAXIMUM Value base on rmcMaxNumMLTBCActions
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 5, 9, 1, 3, 0, 0}, {MAX_FLOWRATE_THRESHOLD, 0, 0, 0}, NO_FILE, ACCESS_P, 1, 8, OBJT_INT1, &hdlr_rmcMLActionTable, "rmcTBMLUsageMode", &tMLUsageMode}, //Needs review: MAXIMUM Value base on rmcMaxNumMLTBCActions
    // // Mainline Timebase Control Action Table - En

    // //{NTCIP_1207, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcPHYSICAL INPUT / OUTPUT OBJECTS", NULL},
    {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcAdvSignOutNumber, "rmcAdvSignOutNumber", NULL},

    // // Mainline Lane Physical Input Table - Begin
    // // NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 2, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcMainline Lane Physical Input Table", NULL},
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 2, 1, 1, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMLInTable, "rmcMLLeadInNumber", NULL}, //Needs review: MAXIMUM Value based on rmcMLNumber
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 2, 1, 2, 0, 0}, {MAX_MAINLINE_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMLInTable, "rmcMLTrailInNumber", NULL}, //Needs review: MAXIMUM Value based on rmcMLNumber
    // // Mainline Lane Physical Input Table - End

    // // Queue Detector Physical Input Table - Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 3, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcQueue Detector Physical Input Table", NULL},
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 3, 1, 1, 0, 0}, {MAX_METERING_LANES, MAX_QUEUES, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcQueueInTable, "rmcMetQueueInNumber", NULL}, //Needs review: MAXIMUM Value based on rmcMeterNumber and rmcQueueNum
    // // Queue Detector Physical Input Table - End

    // // Metered Lane Physical Input/Output Table - Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 4, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_P, 0x0, INT8U_MAX, OBJT_INT1, &hdlr_, "rmcMetered Lane Physical Input/Output Table", NULL},
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 4, 1, 1, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterInOutTable, "rmcMeterDemandInNumber", NULL}, //Needs review: MAXIMUM Value based on rmcMeterNumber
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 4, 1, 2, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterInOutTable, "rmcMeterPassageInNumber", NULL}, //Needs review: MAXIMUM Value based on rmcMeterNumber
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 4, 1, 3, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterInOutTable, "rmcMeterRedOutNumber", NULL}, //Needs review: MAXIMUM Value based on rmcMeterNumber
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 4, 1, 4, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterInOutTable, "rmcMeterYellowOutNumber", NULL}, //Needs review: MAXIMUM Value based on rmcMeterNumber
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 4, 1, 5, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterInOutTable, "rmcMeterGreenOutNumber", NULL}, //Needs review: MAXIMUM Value based on rmcMeterNumber
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 4, 1, 6, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcMeterInOutTable, "rmcAdvSignOutNumber", NULL}, //Needs review: MAXIMUM Value based on rmcMeterNumber
    // // Metered Lane Physical Input/Output Table - End

    // // Dependency Group Physical Input/Output Table - Begin
    // //{NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 5, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_, 0x0, MAX, OBJT_INT1, &hdlr_, "rmcDependency Group Physical Input/Output Table", NULL},
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 5, 1, 0, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependInOutTable, "rmcDependMergeInNumber", NULL}, //Needs review: MAXIMUM Value based on rmcDependGroupNumber
    // {NTCIP_1207, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 2, 6, 5, 1, 0, 0, 0}, {MAX_METERING_LANES, 0, 0, 0}, NO_FILE, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_rmcDependInOutTable, "rmcDependAdvSignOutNumber", NULL}, //Needs review: MAXIMUM Value based on rmcDependGroupNumber
    // // Dependency Group Physical Input/Output Table - End

    // *********************************************************************RAMPMETER ENDS*********************************************************************************************************

    // globalConfiguration - NTCIP 1201
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 1, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_globalSetIDParameter, "globalSetIDParameter", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 1, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_GLOBALMODULES, OBJT_INT1, &hdlr_actionMax, "globalMaxModules", NULL},

    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 1, 3, 1, 1, 0, 0}, {MAX_GLOBALMODULES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_globalModuleTable, "moduleNumber", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 1, 3, 1, 2, 0, 0}, {MAX_GLOBALMODULES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 68, OBJT_OCTET, &hdlr_globalModuleTable, "moduleDeviceNode", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 1, 3, 1, 3, 0, 0}, {MAX_GLOBALMODULES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 68, OBJT_DISPLAY_STR, &hdlr_globalModuleTable, "moduleMake", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 1, 3, 1, 4, 0, 0}, {MAX_GLOBALMODULES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 68, OBJT_DISPLAY_STR, &hdlr_globalModuleTable, "moduleModel", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 1, 3, 1, 5, 0, 0}, {MAX_GLOBALMODULES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 68, OBJT_DISPLAY_STR, &hdlr_globalModuleTable, "moduleVersion", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 1, 3, 1, 6, 0, 0}, {MAX_GLOBALMODULES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_globalModuleTable, "moduleType", NULL},

    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 1, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX + 1, OBJT_DISPLAY_STR, &hdlr_controllerBaseStandards, "controllerBaseStandards", NULL},

    // globalDBManagement - NTCIP 1201
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 2, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT8U_MAX, OBJT_INT1, &hdlr_dbCreateTransaction, "dbCreateTransaction", &tDbTransaction},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 2, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_dbVerifyStatus, "dbVerifyStatus", &tDbStatus},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 2, 7, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, 200, OBJT_DISPLAY_STR, &hdlr_dbVerifyError, "dbVerifyError", NULL},

    // globalTimeManagement - NTCIP 1201
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RW, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_globalTime, "globalTime", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, MAX_DST_VALUE, OBJT_INT1, &hdlr_globalDaylightSaving, "globalDaylightSaving", &tGlobalDST},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_TBC_SCHEDULES, OBJT_INT2, &hdlr_actionMax, "maxTimeBaseScheduleEntries", NULL},

    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 2, 1, 1, 0}, {MAX_TBC_SCHEDULES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT16U_MAX, OBJT_INT2, &hdlr_timeBaseScheduleTable, "timeBaseScheduleNumber", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 2, 1, 2, 0}, {MAX_TBC_SCHEDULES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT16U_MAX, OBJT_INT2, &hdlr_timeBaseScheduleTable, "timeBaseScheduleMonth", &tSchedMonth},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 2, 1, 3, 0}, {MAX_TBC_SCHEDULES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_timeBaseScheduleTable, "timeBaseScheduleDay", &tSchedDay},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 2, 1, 4, 0}, {MAX_TBC_SCHEDULES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT32U_MAX, OBJT_INT4, &hdlr_timeBaseScheduleTable, "timeBaseScheduleDate", &tSchedDate},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 2, 1, 5, 0}, {MAX_TBC_SCHEDULES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_TBC_DAYPLANS, OBJT_INT1, &hdlr_timeBaseScheduleTable, "timeBaseScheduleDayPlan", NULL},

    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 3, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_TBC_DAYPLANS, OBJT_INT1, &hdlr_actionMax, "maxDayPlans", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 4, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_TBC_EVENTS, OBJT_INT1, &hdlr_actionMax, "maxDayPlanEvents", NULL},

    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 5, 1, 1, 0}, {MAX_TBC_DAYPLANS, MAX_TBC_EVENTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_timeBaseDayPlanTable, "dayPlanNumber", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 5, 1, 2, 0}, {MAX_TBC_DAYPLANS, MAX_TBC_EVENTS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_timeBaseDayPlanTable, "dayPlanEventNumber", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 5, 1, 3, 0}, {MAX_TBC_DAYPLANS, MAX_TBC_EVENTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 23, OBJT_INT1, &hdlr_timeBaseDayPlanTable, "dayPlanHour", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 5, 1, 4, 0}, {MAX_TBC_DAYPLANS, MAX_TBC_EVENTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 59, OBJT_INT1, &hdlr_timeBaseDayPlanTable, "dayPlanMinute", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 5, 1, 5, 0}, {MAX_TBC_DAYPLANS, MAX_TBC_EVENTS, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, SIZE_ACTIONOID, OBJT_OID, &hdlr_timeBaseDayPlanTable, "dayPlanActionNumberOID", NULL}, // Fix

    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 6, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_dayPlanStatus, "dayPlanStatus", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 3, 7, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_timeBaseScheduleTableStatus, "timeBaseScheduleTableStatus", NULL},

    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 4, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, MIN_TZ_OFFSET, MAX_TZ_OFFSET, OBJT_SIGN_INT4, &hdlr_globalLocalTimeDifferential, "globalLocalTimeDifferential", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, MIN_TZ_OFFSET, MAX_TZ_OFFSET, OBJT_SIGN_INT4, &hdlr_controllerStandardTimeZone, "controllerStandardTimeZone", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 6, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_controllerLocalTime, "controllerLocalTime", NULL},

    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 1, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_DST_ENTRIES, OBJT_INT1, &hdlr_actionMax, "maxDaylightSavingEntries", NULL},

    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 2, 1, 1, 0}, {MAX_DST_ENTRIES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, MAX_DST_ENTRIES, OBJT_INT1, &hdlr_dstTable, "dstEntryNumber", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 2, 1, 2, 0}, {MAX_DST_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, DST_MONTH_JAN, DST_MONTH_DISABLE, OBJT_INT1, &hdlr_dstTable, "dstBeginMonth", &tDSTMonth},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 2, 1, 3, 0}, {MAX_DST_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, DST_OCCURRENCES_FIRST, DST_OCCURRENCES_SPECIFIC_DAY_OF_MONTH, OBJT_INT1, &hdlr_dstTable, "dstBeginOccurrences", &tDSTOccur},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 2, 1, 4, 0}, {MAX_DST_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, SUNDAY, SATURDAY, OBJT_INT1, &hdlr_dstTable, "dstBeginDayOfWeek", &tDayOfWeek},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 2, 1, 5, 0}, {MAX_DST_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 31, OBJT_INT1, &hdlr_dstTable, "dstBeginDayOfMonth", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 2, 1, 6, 0}, {MAX_DST_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT32U_MAX, OBJT_INT4, &hdlr_dstTable, "dstBeginSecondsToTransition", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 2, 1, 7, 0}, {MAX_DST_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, DST_MONTH_JAN, DST_MONTH_DEC, OBJT_INT1, &hdlr_dstTable, "dstEndMonth", &tDSTMonth},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 2, 1, 8, 0}, {MAX_DST_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, DST_OCCURRENCES_FIRST, DST_OCCURRENCES_SPECIFIC_DAY_OF_MONTH, OBJT_INT1, &hdlr_dstTable, "dstEndOccurrences", &tDSTOccur},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 2, 1, 9, 0}, {MAX_DST_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, SUNDAY, SATURDAY, OBJT_INT1, &hdlr_dstTable, "dstEndDayOfWeek", &tDayOfWeek},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 2, 1, 10, 0}, {MAX_DST_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, 31, OBJT_INT1, &hdlr_dstTable, "dstEndDayOfMonth", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 2, 1, 11, 0}, {MAX_DST_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT32U_MAX, OBJT_INT4, &hdlr_dstTable, "dstEndSecondsToTransition", NULL},
    {NTCIP_1201a, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 3, 7, 2, 1, 12, 0}, {MAX_DST_ENTRIES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, MAX_DST_SECONDS, OBJT_INT2, &hdlr_dstTable, "dstSecondsToAdjust", NULL},

    // globalReport - NTCIP 1103
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_EVENTLOGCONFIGS, OBJT_INT2, &hdlr_actionMax, "maxEventLogConfigs", NULL},

    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 2, 1, 1, 0, 0}, {NUM_EVENTLOGCONFIGS, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT16U_MAX, OBJT_INT2, &hdlr_eventLogConfigTable, "eventConfigID", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 2, 1, 2, 0, 0}, {NUM_EVENTLOGCONFIGS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 1, INT8U_MAX, OBJT_INT1, &hdlr_eventLogConfigTable, "eventConfigClass", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 2, 1, 3, 0, 0}, {NUM_EVENTLOGCONFIGS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, EVENTMODEOTHER, EVENTMODEANDEDWITHVALUE, OBJT_INT1, &hdlr_eventLogConfigTable, "eventConfigMode", &tEvConfMode},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 2, 1, 4, 0, 0}, {NUM_EVENTLOGCONFIGS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, INT32S_MIN, INT32S_MAX, OBJT_INT_UNRES, &hdlr_eventLogConfigTable, "eventConfigCompareValue", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 2, 1, 5, 0, 0}, {NUM_EVENTLOGCONFIGS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, INT32S_MIN, INT32S_MAX, OBJT_INT_UNRES, &hdlr_eventLogConfigTable, "eventConfigCompareValue2", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 2, 1, 6, 0, 0}, {NUM_EVENTLOGCONFIGS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, SIZE_EVTCFGCOMPOID, OBJT_OID, &hdlr_eventLogConfigTable, "eventConfigCompareOID", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 2, 1, 7, 0, 0}, {NUM_EVENTLOGCONFIGS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, SIZE_EVTCFGLOGOID, OBJT_OID, &hdlr_eventLogConfigTable, "eventConfigLogOID", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 2, 1, 8, 0, 0}, {NUM_EVENTLOGCONFIGS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, EVENTACTIONOTHER, EVENTACTIONLOG, OBJT_INT1, &hdlr_eventLogConfigTable, "eventConfigAction", &tEvConfAction},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 2, 1, 9, 0, 0}, {NUM_EVENTLOGCONFIGS, 0, 0, 0}, NO_FILE, ACCESS_RD, EVENTACTIONOTHER, EVENTSTATUSERROR, OBJT_INT1, &hdlr_eventLogConfigTable, "eventConfigStatus", &tEvConfAction},

    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 3, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_EVENTLOGS, OBJT_INT2, &hdlr_actionMax, "maxEventLogSize", NULL},

    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 4, 1, 1, 0, 0}, {8, NUM_EVENTLOGS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_eventLogTable, "eventLogClass", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 4, 1, 2, 0, 0}, {8, NUM_EVENTLOGS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_eventLogTable, "eventLogNumber", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 4, 1, 3, 0, 0}, {8, NUM_EVENTLOGS, 0, 0}, NO_FILE, ACCESS_RD, 1, INT16U_MAX, OBJT_INT2, &hdlr_eventLogTable, "eventLogID", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 4, 1, 4, 0, 0}, {8, NUM_EVENTLOGS, 0, 0}, NO_FILE, ACCESS_RD, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_eventLogTable, "eventLogTime", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 4, 1, 5, 0, 0}, {8, NUM_EVENTLOGS, 0, 0}, NO_FILE, ACCESS_RD, 0, SIZE_EVENTLOGVALUE, OBJT_OPAQUE, &hdlr_eventLogTable, "eventLogValue", NULL},

    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 5, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, NUM_EVENTCLASSES, OBJT_INT1, &hdlr_actionMax, "maxEventClasses", NULL},

    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 6, 1, 1, 0, 0}, {NUM_EVENTCLASSES, 0, 0, 0}, NO_FILE, ACCESS_RD, 1, INT8U_MAX, OBJT_INT1, &hdlr_eventClassTable, "eventClassNumber", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 6, 1, 2, 0, 0}, {NUM_EVENTCLASSES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT8U_MAX, OBJT_INT1, &hdlr_eventClassTable, "eventClassLimit", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 6, 1, 3, 0, 0}, {NUM_EVENTCLASSES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, INT32U_MAX, OBJT_COUNTER, &hdlr_eventClassTable, "eventClassClearTime", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 6, 1, 4, 0, 0}, {NUM_EVENTCLASSES, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P, 0, 50, OBJT_DISPLAY_STR, &hdlr_eventClassTable, "eventClassDescription", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 6, 1, 5, 0, 0}, {NUM_EVENTCLASSES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT8U_MAX, OBJT_INT1, &hdlr_eventClassTable, "eventClassNumRowsInLog", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 6, 1, 6, 0, 0}, {NUM_EVENTCLASSES, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_eventClassTable, "eventClassNumEvents", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 4, 7, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD, 0, INT16U_MAX, OBJT_INT2, &hdlr_numEvents, "numEvents", NULL},

    // security -  - NTCIP 1103
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 5, 1, 0, 0, 0, 0}, {0, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P | AF_COMTY, 8, 16, OBJT_DISPLAY_STR, &hdlr_communityNameAdmin, "communityNameAdmin", NULL}, // NTCIP 1103 SECURITY GROUP
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 5, 2, 0, 0, 0, 0}, {0, 0, 0, 0}, NO_FILE, ACCESS_RD | AF_COMTY, 1, MAX_SECURITY_USERS, OBJT_INT1, &hdlr_actionMax, "communityNamesMax", NULL},

    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 5, 3, 1, 1, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, NO_FILE, ACCESS_RD | AF_COMTY, 1, MAX_SECURITY_USERS, OBJT_INT1, &hdlr_communityNameTable, "communityNameIndex", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 5, 3, 1, 2, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P | AF_COMTY, 6, 16, OBJT_DISPLAY_STR, &hdlr_communityNameTable, "communityNameUser", NULL},
    {NTCIP_1103b, {1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 5, 3, 1, 3, 0, 0}, {MAX_SECURITY_USERS, 0, 0, 0}, ENUM_FLASH_AREA_PARAMETERS, ACCESS_P | AF_COMTY, 0, INT32U_MAX, OBJT_GAUGE, &hdlr_communityNameTable, "communityNameAccessMask", NULL},

    {-1, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0}, 0, 0, 0, 0, 0, NULL, "End", NULL} // end rowIdx for TYPE_OIDTABLE OID[]

};

/*************************************************************************************************/
/*  Name       : hdlr_actionMax                                                                  */
/*                                                                                               */
/*  Description: it responds with the the oidMax value from the OID table structure.             */
/*               Used for read-only objects that return a fixed max value oidMax is              */
/*               interpreted as an long value according to net-snmp library                      */
/*                                                                                               */
/*       return: SNMP_ERR_NOERROR                                                                */
/*************************************************************************************************/
int hdlr_actionMax(netsnmp_request_info *requests, const TYPE_OIDTABLE *this)
{
  long temp;

  temp = this->oidMax;
  snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, &temp, sizeof(temp));

  return SNMP_ERR_NOERROR;
}

/*************************************************************************************************/
/*  Name       : hdlr_mcAtcGenericDeprecatedObject                                               */
/*                                                                                               */
/*  Description: Handler to be used for all Deprecated OIDs. If a SET is requested               */
/*               it responds with the same data that just arrived. If a GET is requested         */
/*               it builds the response based on the deprecated OID type and its minimum value.  */
/*************************************************************************************************/
int hdlr_mcAtcGenericDeprecatedObject(netsnmp_request_info *requests, const TYPE_OIDTABLE *this)
{
  int mode = requests->agent_req_info->mode;
  int ret = SNMP_ERR_NOERROR; // expect no errors
  long temp = 0;
  void *ptrTemp = &temp;
  u_char type = ASN_NULL;
  char octTemp[MAX_OCTET_LENGTH] = {0};
  int sizeValue = sizeof(temp);

  if (mode == MODE_SET_ACTION) {
    //                       *** Do not set incoming  values ***
    // Notes:
    // 1. There is an previous verification of valid values to set in mibModules.c so,
    //    if the value are correct this part of code will execute doing nothing. If the
    //    value if wrong, the agent (snmpMA) return a snmp error to manager
    //
    // 2. The agent (snmpMA) will send the received package to manager as set response
    //
  } else { // GET or GETNEXT

    if (bIsOctet(this->oidType) == TRUE) {                                              // Check the type of OID
      ptrTemp = octTemp;                                                                // octTemp has zeros values
      sizeValue = (this->oidType == OBJT_DISPLAY_STR ? strlen(octTemp) : this->oidMin); // size of string or the Octet array to return

    } else {
      temp = this->oidMin; // get the minimum value for this Object from OIDTable
    }
    // create response
    type = u8OMNItoASNtype[this->oidType]; // translate the OMNI object type to ASN type used by net-snmp library.
    snmp_set_var_typed_value(requests->requestvb, type, ptrTemp, sizeValue);
  }

  return ret;
} // hdlr_mcAtcGenericDeprecatedObject()

/*************************************************************************************************/
/*  Name       : u8IndexLen                                                                      */
/*                                                                                               */
/*  Description: return the quantity of indices are present in the array pointed by au16Index.   */
/*                 minimum  = 0                                                                  */
/*                 maximum  = MA_MAX_OID_INDICES  ( 4 indices )                                  */
/*                                                                                               */
/*************************************************************************************************/
INT8U u8IndexLen(INT16U *au16Index)
{
  int u8Size = 0;

  for (u8Size = 0; u8Size < MA_MAX_OID_INDICES; u8Size++) {
    if (au16Index[u8Size] == 0)
      break;
  }

  return u8Size;
}

INT8U snmp_oid_len(oid *oidNum)
{
  INT8U u8size = 0;

  for (u8size = 0; u8size < NETSNMP_LEN_OID_PART; u8size++) {
    if (oidNum[u8size] == 0)
      break;
  }

  return u8size;
}

void snmp_oid_print(oid *OidNum, INT8U size)
{

  int i = 0;
  if (size == 0) {
    size = snmp_oid_len(OidNum);
  }

  for (i = 0; i < size; i++) {
    printf(".%ld", OidNum[i]);
  }
  printf("\n");
}

void snmp_oid_cpy(oid *oidDst, const oid *oidSrc, INT8U u8Size)
{
  memcpy(oidDst, oidSrc, u8Size * sizeof(oid));
}

/*************************************************************************************************/
/*  Name       : bIsValidRange                                                                   */
/*                                                                                               */
/*  Description: Function to check if the value to write is in valid range of the OID            */
/*                                                                                               */
/*       Return: TRUE is value is valid and FALSE otherwise.                                     */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN bIsValidRange(netsnmp_request_info *requests, const TYPE_OIDTABLE *oid)
{

  INT32U u32Val = 0;
  INT32S s32Val = 0;
  INT16U u16Len = 0;

  switch (oid->oidType) {

    case OBJT_INT1:
    case OBJT_INT2:
    case OBJT_INT4:
      u32Val = (INT32U)(*requests->requestvb->val.integer); // use 32bit to avoid truncated value
      return (u32Val < oid->oidMin || u32Val > oid->oidMax ? FALSE : TRUE);
      break;

    case OBJT_SIGN_INT1:
    case OBJT_SIGN_INT2:
    case OBJT_SIGN_INT4:
      s32Val = (INT32S)(*requests->requestvb->val.integer); // use 32bits to avoid truncated value
      return (s32Val < oid->oidMin || s32Val > oid->oidMax ? FALSE : TRUE);
      break;

    case OBJT_OCTET:
    case OBJT_DISPLAY_STR:
    case OBJT_IP_ADDR:                                 // OCTET size (4) in oidMin and oidMax -- SIZE_IPv4_ADDRESS
    case OBJT_PHYS_ADDR:                               // OCTET size (6) in oidMin and oidMax -- PHYSICAL_ADDRESS_LENGTH
      u16Len = (INT16U)requests->requestvb->val_len;   // Length of incoming value.
      if (oid->oidMin == oid->oidMax) {                // If the oidMin and oidMax are equal, the OCTET must
        return (u16Len == oid->oidMax ? TRUE : FALSE); // must be equal to that.
      } else {                                         // The incoming OCTET must be less or equal to
        return (u16Len <= oid->oidMax ? TRUE : FALSE); // oidMax valid
      }
      break;

    case OBJT_NULL:
      break;

    case OBJT_OID:
      // -- Bypass OBJT_OID (by now) --
      return TRUE;
      break;

    case OBJT_COUNTER:
    case OBJT_GAUGE:
    case OBJT_TIME_TICKS:                                   // IMPLICIT INTEGER (0..4294967295)
      u32Val = (INT32U)(*requests->requestvb->val.integer); // incoming value
      return (u32Val < oid->oidMin || u32Val > oid->oidMax ? FALSE : TRUE);
      break;

    case OBJT_INT_UNRES:                                    // Lan: requiere a Fix
      s32Val = (INT32S)(*requests->requestvb->val.integer); // use 32bit to avoid truncated value
      return (s32Val < oid->oidMin || s32Val > oid->oidMax ? FALSE : TRUE);
      break;

    default:
      break;

  } // case

  return FALSE;

} // bIsInValidRange

/*************************************************************************************************/
/*  Name       : bIsScalarOID                                                                    */
/*                                                                                               */
/*  Description: Function to check if an OID bellows to scalar object                            */
/*                                                                                               */
/*       Return: TRUE is object OID is a scalar and FALSE otherwise.                             */
/*               In addition, returns in pu8QtyIdx the quantity of index if the OID object       */
/*               is a table, and zero for scalar OID objects.                                   */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN bIsScalarOID(TYPE_OIDTABLE *oid, INT8U *pu8QtyIdx)
{

  *pu8QtyIdx = u8IndexLen(oid->oidIndexMax);
  if (*pu8QtyIdx == 0) { // no indexes, it is scalar
    return TRUE;
  } else {
    return FALSE;
  }
}

/*************************************************************************************************/
/*  Name       : bIsOctet                                                                        */
/*                                                                                               */
/*  Description: Function to check if an OID bellows to Octect type object                       */
/*                                                                                               */
/*       Return: TRUE is object OID is a octect and FALSE otherwise.                             */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN bIsOctet(INT8U OMNItype)
{

  switch (OMNItype) {

    case OBJT_OCTET:
    case OBJT_IP_ADDR:
    case OBJT_DISPLAY_STR:
    case OBJT_PHYS_ADDR:
    case OBJT_OWNER_STR:
    case OBJT_OID:
    case OBJT_OPAQUE:
      return TRUE;

    default:
      break;
  }

  return FALSE;
}

/*************************************************************************************************/
/*  Name       : OMNItoASNtype                                                                   */
/*                                                                                               */
/*  Description: Function to convert an OMNI object type to ASN1 objec type used in              */
/*               net-snmp library.                                                               */
/*                                                                                               */
/*************************************************************************************************/
// INT8U OMNItoASNtype(INT8U OMNItype)
// {

//   switch (OMNItype) {
//     case OBJT_INT1 ... OBJT_INT_UNRES: //!< NTCIP identifier = 0x02
//       return ASN_INTEGER;

//     case OBJT_OCTET ... OBJT_OWNER_STR: // NTCIP identifier = 0x04
//       return ASN_OCTET_STR;

//     case OBJT_NULL: // NTCIP identifier = 0x05
//       return ASN_NULL;

//     case OBJT_OID: // NTCIP identifier = 0x06
//       return ASN_OBJECT_ID;

//     case OBJT_IP_ADDR:      // NTCIP identifier = 0x40  IMPLICIT OCTET STRING (SIZE (4)), in network-byte order (IpAddress)
//       return ASN_IPADDRESS; // ASN_IPADDRESS

//     case OBJT_COUNTER: // NTCIP identifier = 0x41  IMPLICIT INTEGER (0..4294967295) wraps
//       return ASN_COUNTER;

//     case OBJT_GAUGE: // NTCIP identifier = 0x42  IMPLICIT INTEGER (0..4294967295) no wrap
//       return ASN_GAUGE;

//     case OBJT_TIME_TICKS: // NTCIP identifier = 0x43  IMPLICIT INTEGER (0..4294967295) no wrap (TimeTicks)
//       return ASN_TIMETICKS;

//     case OBJT_OPAQUE:
//       return ASN_OPAQUE;

//     default:
//       break;
//   }
//   return 0;
//}

/*************************************************************************************************/
/*  Name       : bSnmpGetbyRowTable                                                              */
/*                                                                                               */
/*  Description: Function snmpget invoked using an specific OID  and indices.                    */
/*               The value and lengh of the read object is stored in a value buffer and length   */
/*               parameters.                                                                     */
/*                                                                                               */
/*       Return: Type snmp error.                                                                */
/*                                                                                               */
/*   Example:                                                                                    */
/*            oid sysDescrOID[MAX_OID_LENGTH] = {1, 3, 6, 1, 2, 1, 1, 1, 0};  // scalar          */
/*            INT8U temp[40] = {0};                                                              */
/*            size_t len;                                                                        */
/*                                                                                               */
/*            u8SnmpGetbyOID(sysDescrOID, NULL, temp, &len);                                     */
/*            printf("get data: %s \n", temp);                                                   */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN bSnmpGetbyOID(oid *reqOID, INT16U *u16Indices, u_char *value, size_t *len, INT16U *u16Err)
{
  BOOLEAN bRet = FALSE;
  // INT8U errResult = SNMP_ERR_NOERROR;
  BOOLEAN bEndZero = FALSE; //  no used
  INT16U u16Row = 0;

  netsnmp_agent_request_info info = {mode : MODE_GET};                            // force mode as a GET operation
  netsnmp_variable_list var_list = {0};                                           // create var and init to zero
  netsnmp_request_info request = {agent_req_info : &info, requestvb : &var_list}; // force request to use info and var
  netsnmp_request_info *ptReq = &request;                                         // use a pointer to request

  // setup the request info before invoke bFindOID() fuction
  ptReq->requestvb->name = reqOID;                      // use incoming reqOID
  ptReq->requestvb->name_length = snmp_oid_len(reqOID); // set length according to reqOID

  printf("u8SnmpGetbyOID: reading OID(%d):", ptReq->requestvb->name_length), snmp_oid_print(ptReq->requestvb->name, ptReq->requestvb->name_length);

  if (bFindOID(ptReq, &u16Row, &bEndZero, TRUE) == TRUE) {
    printf("Found Row: %d and invoking oid handler\n", u16Row);           //
    bRet = bSnmpGetbyRowOIDTable(u16Row, u16Indices, value, len, u16Err); // invoke handler of the u16Row row
  } else {
    printf("reading test OID: Not Found\n");
    *u16Err = SNMP_ERR_NOSUCHNAME;
    return FALSE;
  }

  return bRet;
}

/*************************************************************************************************/
/*  Name       : u8SnmpGetbyRowTable                                                              */
/*                                                                                               */
/*  Description: Function snmpget invoked using an specific row of the OID table and indices.    */
/*               The value and lengh of the read object is stored in a value buffer and length   */
/*               parameters.                                                                     */
/*                                                                                               */
/*       Return: Type snmp error.                                                                */
/*                                                                                               */
/*   Example:                                                                                    */
/*            INT8U temp[40] = {0};                                                              */
/*            size_t len;                                                                        */
/*                                                                                               */
/*            u8SnmpGetbyRowOIDTable(0, NULL, temp, &len);  // get row 0 OID: "sysDescr"         */
/*            printf("get data: %s \n", temp);                                                   */
/*                                                                                               */
/*************************************************************************************************/
netsnmp_agent_request_info info = {mode : MODE_GET};                            // force mode as a GET operation
netsnmp_variable_list var_list = {0};                                           // create var and init to zero
netsnmp_request_info request = {agent_req_info : &info, requestvb : &var_list}; // force request to use info and var

BOOLEAN bSnmpGetbyRowOIDTable(INT16U u16Row, INT16U *pu16Indices, void *pvValue, size_t *pu32Len, INT16U *pu16Err)
{
  BOOLEAN bRet = TRUE;
  size_t u32LenTmp = 0;
  INT8U u8SizeOid = 0;
  INT8U u8ReqQtyIdx = 0;
  INT8U u8RowOidQtyIdx = 0;
  INT8U u8Idx = 0;
  BOOLEAN bIsOctet = FALSE;
  BOOLEAN bIsNumeric = FALSE;

  // netsnmp_agent_request_info info = {mode : MODE_GET};                            // force mode as a GET operation
  // netsnmp_variable_list var_list = {0};                                           // create var and init to zero
  // netsnmp_request_info request = {agent_req_info : &info, requestvb : &var_list}; // force request to use info and var
  netsnmp_request_info *ptReq = &request; // use a pointer to request

  *pu16Err = SNMP_ERR_NOERROR;

  // printf("Starting: bSnmpGetbyRowOIDTable \n ");
  // setup the request info before invoke the function handler
  ptReq->requestvb->name_length = snmp_oid_len(OID[u16Row].oidNum); // set length according to oidNum
  u8SizeOid = ptReq->requestvb->name_length;                        // last oid element to allocate

  // copy oidNum fron OID table to be used as oid for the request
  memcpy(ptReq->requestvb->name_loc, OID[u16Row].oidNum, u8SizeOid * sizeof(oid));
  ptReq->requestvb->name = ptReq->requestvb->name_loc;

  // printf("req OID(%d) :", u8SizeOid), snmp_oid_print(ptReq->requestvb->name, u8SizeOid);
  //  printf("name_loc OID(%d) :", u8SizeOid), snmp_oid_print(ptReq->requestvb->name, u8SizeOid);

  if (bIsScalarOID(&OID[u16Row], &u8RowOidQtyIdx) == FALSE) {
    if (pu16Indices == NULL) {        // it is a table, then check the incoming indices
      *pu16Err = SNMP_ERR_NOSUCHNAME; // requesting table without using indices
      return FALSE;
    }
    u8ReqQtyIdx = u8IndexLen(pu16Indices); // get qty of indices
    // printf("Qty Index: %d ", u8ReqQtyIdx);
    if (u8ReqQtyIdx != u8RowOidQtyIdx) {
      *pu16Err = SNMP_ERR_NOSUCHNAME; // request OID indices doesn't match whith row OID indeces
      return FALSE;
    }

    //  printf("OID: %s => ", OID[u16Row].pcOidName);
    //  printf("OID Size: %d  Index[ %d %d %d %d ] => ", u8SizeOid, pu16Indices[0], pu16Indices[1], pu16Indices[2], pu16Indices[3]);

    for (u8Idx = 0; u8Idx < u8ReqQtyIdx; u8Idx++) { // complete the OID including the indices
      ptReq->requestvb->name[u8SizeOid + u8Idx] = pu16Indices[u8Idx];
    }
    u8SizeOid += u8ReqQtyIdx;
    ptReq->requestvb->name_length = u8SizeOid;
  }

  //  printf("OID(%d): ", u8SizeOid), snmp_oid_print(ptReq->requestvb->name, u8SizeOid);
  //  printf("Invoking handler: %s => ", OID[u16Row].pcOidName);

  *pu16Err = OID[u16Row].ptrOidAction(ptReq, &OID[u16Row]); // invoke handler
  // printf("Returned from handler: %s \n", OID[u16Row].pcOidName);

  if (*pu16Err != SNMP_ERR_NOERROR) {
    return FALSE;
  }

  bRet = TRUE;
  u32LenTmp = u16Get_OER_MaxSize(&OID[u16Row], &bIsOctet, &bIsNumeric); // leng used to encoding BER format

  // alocate the read object data into return parameters
  if (bIsOctet == TRUE) {
    // printf("Is OCTET ");
    *pu32Len = ptReq->requestvb->val_len;
    if ((OID[u16Row].oidType == OBJT_OID) && (ptReq->requestvb->val.string[0] == 0)) { // use short format for null oid objects
      *pu32Len = 0;
    } else {
      memcpy((INT8U *)pvValue, ptReq->requestvb->val.string, *pu32Len);
    }

  } else if (bIsNumeric == TRUE) {
    *((long *)pvValue) = (long)*(ptReq->requestvb->val.integer); // copy value (all number are long type in net-snmp)
    *pu32Len = u32LenTmp;                                        // size required according to OER_MaxSize
  } else {                                                       // unknow OID type
    *pu16Err = SNMP_ERR_GENERR;
    bRet = FALSE;
  }

  return bRet;
}

/*************************************************************************************************/
/*  Name       : bSnmpSetbyOID                                                                   */
/*                                                                                               */
/*  Description: Function snmpset invoked using an specific OID and indices.                     */
/*               The object value to write requieres the type and length parameters according    */
/*               as used in the net-snmp library.                                                */
/*                                                                                               */
/*       Return: Type snmp error.                                                                */
/*                                                                                               */
/*   Example:                                                                                    */
/*            oid sysNameOID[MAX_OID_LENGTH] = {1, 3, 6, 1, 2, 1, 1, 5, 0};                      */
/*            INT8U temp[40] = {"test"};                                                         */
/*                                                                                               */
/*            u8SnmpSetbyOID(sysNameOID, NULL, ASN_OCTET_STR, temp, strlen((char *)temp));       */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN b8SnmpSetbyOID(oid *reqOID, INT16U *u16Indices, u_char type, void *value, size_t len, INT16U *u16Err)
{
  BOOLEAN bRet = FALSE;
  BOOLEAN bEndZero = FALSE; // no used
  INT16U u16Row = 0;
  netsnmp_agent_request_info info = {mode : MODE_SET_ACTION};                     // force mode as a SET operation
  netsnmp_variable_list var_list = {0};                                           // create var and init to zero
  netsnmp_request_info request = {agent_req_info : &info, requestvb : &var_list}; // force request to use info and var
  netsnmp_request_info *ptReq = &request;                                         // use a pointer to request

  // setup the request info before invoke bFindOID() fuction
  ptReq->requestvb->name = reqOID;                                      // use incoming reqOID
  ptReq->requestvb->name_length = snmp_oid_len(ptReq->requestvb->name); // set length according to reqOID

  if (bFindOID(ptReq, &u16Row, &bEndZero, TRUE) == TRUE) {                      //
    bRet = bSnmpSetbyRowOIDTable(u16Row, u16Indices, type, value, len, u16Err); // invoke handler of the u16Row row
  } else {
    *u16Err = SNMP_ERR_NOSUCHNAME;
    bRet = FALSE;
  }

  return bRet;
}

/*************************************************************************************************/
/*  Name       : bSnmpSetbyRowTable                                                              */
/*                                                                                               */
/*  Description: Function snmpset invoked using an specific row of the OID table and indices.    */
/*               The object value to write requieres the type and length parameters according    */
/*               as used in the net-snmp library.                                                */
/*                                                                                               */
/*       Return: Type snmp error.                                                                */
/*                                                                                               */
/*   Example:                                                                                    */
/*            INT8U temp[40] = {0};                                                              */
/*                                                                                               */
/*            // set row 4 OID: ""sysName"                                                       */
/*            strcpy((char *)temp, "test2")                                                      */
/*            u8SnmpSetbyRowOIDTable(4, NULL, ASN_OCTET_STR, temp, strlen((char *)temp));        */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN bSnmpSetbyRowOIDTable(INT16U u16Row, INT16U *pu16Indices, u_char type, void *pvValue, size_t u32Len, INT16U *pu16Err)
{
  // INT8U errResult = SNMP_ERR_NOERROR;
  BOOLEAN bRet = FALSE;
  INT8U u8SizeOid = 0;
  INT8U u8ReqQtyIdx = 0;
  INT8U u8RowOidQtyIdx = 0;
  INT8U u8Idx = 0;
  netsnmp_agent_request_info info = {mode : MODE_SET_ACTION};                // create info force mode as a SET operation
  netsnmp_variable_list var = {0};                                           // create var and init to zero
  netsnmp_request_info request = {agent_req_info : &info, requestvb : &var}; // force request to use info and var
  netsnmp_request_info *ptReq = &request;                                    // use a pointer to request

  // printf("Starting: bSnmpSetbyRowOIDTable \n ");

  if (OID[u16Row].oidAccess == ACCESS_RD) {
    *pu16Err = SNMP_ERR_READONLY; // the Oid to operate must be ACCESS_RW access type
    return FALSE;
  }

  // setup the request info before invoke the function handler
  ptReq->requestvb->name_length = snmp_oid_len(OID[u16Row].oidNum); // set length according to oidNum
  u8SizeOid = ptReq->requestvb->name_length;

  // last oid element to allocate
  // snmp_oid_cpy(ptReq->requestvb->name_loc, OID[u16Row].oidNum, u8SizeOid); // use oidNum from OID table
  memcpy(ptReq->requestvb->name_loc, OID[u16Row].oidNum, u8SizeOid * sizeof(oid));

  ptReq->requestvb->name = ptReq->requestvb->name_loc;

  ptReq->requestvb->type = type;
  ptReq->requestvb->val_len = u32Len;
  ptReq->requestvb->val.string = pvValue;

  if (bIsValidRange(ptReq, &OID[u16Row]) == FALSE) { // Verify if the value to set is in valid range
    *pu16Err = SNMP_ERR_BADVALUE;
    // printf("***Error in range\n");
    return FALSE;
  }

  // printf("name OID(%d) :", u8SizeOid), snmp_oid_print(ptReq->requestvb->name, u8SizeOid);
  //  printf("name_loc OID(%d) :", u8SizeOid), snmp_oid_print(ptReq->requestvb->name, u8SizeOid);

  if (bIsScalarOID(&OID[u16Row], &u8RowOidQtyIdx) == FALSE) {
    if (pu16Indices == NULL) {        // it is a table, then check the incoming indices
      *pu16Err = SNMP_ERR_NOSUCHNAME; // requesting table without using indices
      return FALSE;
    }
    u8ReqQtyIdx = u8IndexLen(pu16Indices); // get qty of indices
    // printf("Qty Index: %d \n", u8ReqQtyIdx);
    if (u8ReqQtyIdx != u8RowOidQtyIdx) {
      *pu16Err = SNMP_ERR_NOSUCHNAME; // request OID indices doesn't match whith row OID indeces
      return FALSE;
    }

    // ptReq->requestvb->name_length += u8ReqQtyIdx;   // update oidNum length
    // printf("OID Size: %d  Index[ %d %d %d %d ]\n", u8SizeOid, pu16Indices[0], pu16Indices[1], pu16Indices[2], pu16Indices[3]);

    // printf("OID: %s => ", OID[u16Row].pcOidName);
    // printf("OID Size: %d  Index[ %d %d %d %d ] => ", u8SizeOid, pu16Indices[0], pu16Indices[1], pu16Indices[2], pu16Indices[3]);

    for (u8Idx = 0; u8Idx < u8ReqQtyIdx; u8Idx++) { // complete the OID including the indices
      ptReq->requestvb->name[u8SizeOid + u8Idx] = pu16Indices[u8Idx];
    }
    u8SizeOid += u8ReqQtyIdx;
    ptReq->requestvb->name_length = u8SizeOid;
  }

  // printf("OID(%d): ", u8SizeOid), snmp_oid_print(ptReq->requestvb->name, u8SizeOid);
  *pu16Err = OID[u16Row].ptrOidAction(ptReq, &OID[u16Row]); // invoke handler

  bRet = (*pu16Err == SNMP_ERR_NOERROR) ? TRUE : FALSE;

  return bRet;
}

/*************************************************************************************************/
/*  Name       : bFindOID                                                                        */
/*                                                                                               */
/*  Description: Seach an OID in the OID table.                                                  */
/*                                                                                               */
/*    Return:    TRUE if successful, FALSE otherwise.                                            */
/*                                                                                               */
/*    This function only reads up to node required for locating the row in the OID table         */
/*    starting from row received by pu16Row. If the return es TRUE pu16Row has the row number    */
/*    where the OID was found.                                                                   */
/*    Note: The OID table must be sorted by the Object ID (OID)                                  */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN bFindOID(netsnmp_request_info *request, INT16U *pu16Row, BOOLEAN *bEndZero, BOOLEAN bChkIndex)
{

  INT16U u16Row = 0;
  INT16U u16StartSearchRowIndex = 0; // First index to search
  INT8U sizeRowOID = 0;
  oid *reqOID = request->requestvb->name;
  INT8U sizeReqOID = request->requestvb->name_length;
  INT8U u8QtyIdx = 0;
  int cmp_res = 0;

  // int count = 0;
  // int countStart = 0;
  // BOOLEAN bSeaarchAgain = FALSE;

  if (sizeReqOID > MAX_SIZE_REQ_OID) {
    return FALSE;
  }

  // printf("\n start0: %d -> %d  ", u16Row, *pu16Row), snmp_oid_print(reqOID, 0);

  if (*pu16Row == 0) {
    if (bFindRowStart(request, &u16Row) == FALSE) {
      printf(" ******* Error OID -- not found:  %s\n", OID[u16Row].pcOidName);
      return SNMP_ERR_NOSUCHNAME;
    }
    // printf("0:Try to find %d stating at %d to find OID: ", *pu16Row, u16Row), snmp_oid_print(reqOID, 0);
    //  u16Row = *pu16Row;               // starting from row received by pu16Row
    u16StartSearchRowIndex = u16Row; // Remember the row to start the search
    // countStart = u16StartSearchRowIndex;
  } else {
    u16Row = *pu16Row;               // starting from row received by pu16Row
    u16StartSearchRowIndex = u16Row; // Remember the row to start the search
    // countStart = u16StartSearchRowIndex;
    //  printf("n:Try to find %d stating at %d to find OID: ", *pu16Row, u16Row), snmp_oid_print(reqOID, 0);
  }
  // printf("Init Start: %d ---> %d\n", u16Row, u16StartSearchRowIndex);

  do {

    sizeRowOID = snmp_oid_len(OID[u16Row].oidNum);
    cmp_res = snmp_oid_ncompare(reqOID, sizeReqOID, OID[u16Row].oidNum, sizeRowOID, sizeRowOID);
    // printf("INIT: sizeReqOID: %d LocOID size: %d  Name: %s res: %d  \n", sizeReqOID, sizeRowOID, OID[u16Row].pcOidName, cmp_res);
    if (cmp_res == 0) {
      // if (count != 1) {
      // printf("bFindOID: %d Start: %4d Row: %4d Count: %4d  [%10s] \tName:%s\n", bSeaarchAgain, countStart, u16Row, count, Labels[OID[u16Row].oidBaseIdx], OID[u16Row].pcOidName);
      //}
      *pu16Row = u16Row;
      // count = 0;
      // bSeaarchAgain = FALSE;

      if (bChkIndex == FALSE) { // required check Oid index ?
        return TRUE;
      }
      // if scalar check for only one possible valid end zero of OID
      if (bIsScalarOID(&OID[u16Row], &u8QtyIdx) == TRUE) {
        if (sizeReqOID == sizeRowOID) { // match -- no end zero of OID
          *bEndZero = FALSE;
          return TRUE;
        }

        if (sizeReqOID == (sizeRowOID + 1) && reqOID[sizeReqOID - 1] == 0) { // end zero of OID
          *bEndZero = TRUE;
          return TRUE;
        }
        return FALSE; // invalid -- it has extra end zeros of OID

      } else {

        // printf("Table: QtyIdx: %d  OID(%d)", u8QtyIdx, sizeReqOID), snmp_oid_print(reqOID, sizeReqOID);

        if (sizeReqOID == sizeRowOID + u8QtyIdx) {
          *bEndZero = FALSE;
          return TRUE;
        }
        if (sizeReqOID == (sizeRowOID + u8QtyIdx + 1) && reqOID[sizeReqOID - 1] == 0) { // one end zero of OID
          *bEndZero = TRUE;
          return TRUE;
        }

        printf("Error: Invalid Table\n");
        return FALSE; // invalid -- it has extra zeros end of OID
      }
    }

    u16Row++; // go to next row
    // count++;

    if (u16Row == u16StartSearchRowIndex) { // Not Found
      break;
    }

    if (OID[u16Row].oidBaseIdx == -1 && u16StartSearchRowIndex != 0) {
      // bSeaarchAgain = TRUE;
      // printf("new: -end: %d --> ", u16Row);
      if (bFindRowStart(request, &u16Row) == FALSE) {
        break;
      }
      if (u16Row >= u16StartSearchRowIndex) {
        break;
      }
      // printf("start: %d ---> %d\n", u16Row, u16StartSearchRowIndex);
    }

  } while (OID[u16Row].oidBaseIdx != -1);

  // printf("\nError: OID not Found\n");
  return FALSE; // Not found
}

/*************************************************************************************************/
/*  Name       : bFindNextOIDrow                                                                 */
/*                                                                                               */
/*  Description: Seach the next OID in the OID table from an OID given.                          */
/*                                                                                               */
/*    Return:    TRUE if successful, FALSE otherwise.                                            */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN bFindNextOID(netsnmp_request_info *requests, INT16U *pu16Row, oid *nxtOID, INT8U *nxtOIDLen)
{
  INT16U u16Row = *pu16Row;
  INT8U sizeRowOID = 0;
  oid *reqOID = requests->requestvb->name;
  INT8U sizeReqOID = requests->requestvb->name_length;
  INT8U u8QtyIdx = 0;
  int cmp_res = 0;

  if (sizeReqOID > MAX_SIZE_REQ_OID) {
    return FALSE;
  }

  do {

    sizeRowOID = snmp_oid_len(OID[u16Row].oidNum);
    cmp_res = snmp_oid_ncompare(reqOID, sizeReqOID, OID[u16Row].oidNum, sizeRowOID, sizeRowOID);

    // printf("%d reqOID(%2d):", cmp_res, sizeReqOID), snmp_oid_print(reqOID, sizeReqOID);
    // printf("%d   OIDt(%2d):", cmp_res, sizeRowOID), snmp_oid_print(OID[u16Row].oidNum, sizeRowOID);

    if (cmp_res <= 0) { //  -1: if rOid<tOid   0:if rOid=tOid    +1: if rOid>tOid
      if (bIsScalarOID(&OID[u16Row], &u8QtyIdx) == TRUE) {
        if (sizeReqOID <= sizeRowOID) { // is the req OID lower than or equal to row OID?
          *nxtOIDLen = ++sizeRowOID;    // complete it as row OID including end zero
          snmp_oid_cpy(nxtOID, OID[u16Row].oidNum, *nxtOIDLen);
          *pu16Row = u16Row;
        } else {
          *pu16Row = u16getNextOID(u16Row, nxtOID, nxtOIDLen); // get next OID
        }

        return TRUE;

      } else {
        if (sizeReqOID <= sizeRowOID || (sizeReqOID == sizeRowOID + 1 && reqOID[sizeReqOID - 1] == 0)) { // is the req OID lower than or equal to row OID?
          *pu16Row = u16getNextRowFirstIndexTableOID(--u16Row, nxtOID, nxtOIDLen);                       // use --16Row to get current one instead of next
          return TRUE;
        }

        if (sizeReqOID > sizeRowOID && reqOID[sizeRowOID] == 0) {
          *pu16Row = u16getNextRowFirstIndexTableOID(--u16Row, nxtOID, nxtOIDLen); // use --16Row to get current one instead of next
          return TRUE;
        }

        // size of reqOID is > than row OID, it is a table and contians indices
        if (u8QtyIdx == 1) {
          if (reqOID[sizeRowOID] >= OID[u16Row].oidIndexMax[0]) {
            *pu16Row = u16getNextOID(u16Row, nxtOID, nxtOIDLen); // next row
          } else {
            snmp_oid_cpy(nxtOID, reqOID, sizeReqOID);
            *nxtOIDLen = sizeReqOID;
            *pu16Row = u16getNextRowIndexTableOID(u16Row, nxtOID, nxtOIDLen);
          }
          return TRUE;
        } else if (u8QtyIdx == 2) {
          if (reqOID[sizeRowOID] >= OID[u16Row].oidIndexMax[0] && reqOID[sizeRowOID + 1] >= OID[u16Row].oidIndexMax[1]) {
            *pu16Row = u16getNextOID(u16Row, nxtOID, nxtOIDLen); // next row
          } else {
            snmp_oid_cpy(nxtOID, reqOID, sizeReqOID);
            *nxtOIDLen = sizeReqOID;
            *pu16Row = u16getNextRowIndexTableOID(u16Row, nxtOID, nxtOIDLen);
          }
          return TRUE;

        } else { // u8QtyIdx > 2
          printf("Error: OMNI does not use objects with 3 or more indexes \n");
          return FALSE;
        }
      }
    }

    u16Row++; // go to next row
  } while (OID[u16Row].oidBaseIdx != -1);

  return FALSE;
}

INT16U u16getNextOID(INT16U u16Row, oid *nxtOID, INT8U *nxtOIDLen)
{
  INT8U u8QtyIdx = 0;

  if (bIsScalarOID(&OID[u16Row + 1], &u8QtyIdx) == TRUE) {               // Is a scalar ?
    u16Row = u16getNextScalarOID(u16Row, nxtOID, nxtOIDLen);             // next OID scalar
  } else {                                                               // it is a table,
    u16Row = u16getNextRowFirstIndexTableOID(u16Row, nxtOID, nxtOIDLen); // so star using first indexes
  }
  return u16Row;
}

INT16U u16getNextScalarOID(INT16U u16Row, oid *nxtOID, INT8U *nxtOIDLen)
{
  INT16U sizeRowOID = 0;
  u16Row++;
  sizeRowOID = snmp_oid_len(OID[u16Row].oidNum) + 1;
  snmp_oid_cpy(nxtOID, OID[u16Row].oidNum, sizeRowOID);
  *nxtOIDLen = sizeRowOID;

  return u16Row;
}

//
INT16U u16getNextRowFirstIndexTableOID(INT16U u16Row, oid *tNxtOID, INT8U *u8NxtOIDLen)
{
  INT16U u16SizeRowOID = 0;
  INT8U u8QtyIdx = 0;

  u16Row++;
  u8QtyIdx = u8IndexLen(OID[u16Row].oidIndexMax);
  u16SizeRowOID = snmp_oid_len(OID[u16Row].oidNum);
  snmp_oid_cpy(tNxtOID, OID[u16Row].oidNum, u16SizeRowOID); // copy base OID
  if (u8QtyIdx == 1) {
    tNxtOID[u16SizeRowOID + 0] = 1;   // include first value of index1
    *u8NxtOIDLen = u16SizeRowOID + 1; // adjust length

  } else if (u8QtyIdx == 2) {
    tNxtOID[u16SizeRowOID + 0] = 1;   // include fists value of index1
    tNxtOID[u16SizeRowOID + 1] = 1;   // include  first value of index2
    *u8NxtOIDLen = u16SizeRowOID + 2; // adjust length
  } else {                            // u8QtyIdx > 2

    printf("Error: OMNI does not use objects with 3 or more indices in oidIndexMax member \n");
  }

  return u16Row;
}

INT16U u16getNextRowIndexTableOID(INT16U u16Row, oid *tNxtOID, INT8U *u8NxtOIDLen)
{
  INT16U u16SizeRowOID = snmp_oid_len(OID[u16Row].oidNum);
  INT8U u8QtyIdx = u8IndexLen(OID[u16Row].oidIndexMax);
  BOOLEAN bIncIdx2 = FALSE;
  BOOLEAN bIncIdx3 = FALSE;
  if (u8QtyIdx == 1) {
    *u8NxtOIDLen = u16SizeRowOID + 1;                                                  // include index1 (row table)
    bIncIdx2 = tNxtOID[*u8NxtOIDLen - 1] == OID[u16Row].oidIndexMax[0] ? TRUE : FALSE; // rollover?
    tNxtOID[*u8NxtOIDLen - 1] %= OID[u16Row].oidIndexMax[0];                           // include next value of index1
    tNxtOID[*u8NxtOIDLen - 1]++;
    tNxtOID[*u8NxtOIDLen - 2] += bIncIdx2 == TRUE ? 1 : 0; // if rollover then include next value
                                                           // of index2 (column table)
  } else if (u8QtyIdx == 2) {
    *u8NxtOIDLen = u16SizeRowOID + 2;                                                  // include index1 and index 2
    bIncIdx2 = tNxtOID[*u8NxtOIDLen - 1] == OID[u16Row].oidIndexMax[1] ? TRUE : FALSE; // rollover in index 1?
    tNxtOID[*u8NxtOIDLen - 1] %= OID[u16Row].oidIndexMax[1];                           // include next value of index2
    tNxtOID[*u8NxtOIDLen - 1]++;

    if (bIncIdx2 == TRUE) {
      bIncIdx3 = tNxtOID[*u8NxtOIDLen - 2] == OID[u16Row].oidIndexMax[0] ? TRUE : FALSE; // rollover in index 2?
      tNxtOID[*u8NxtOIDLen - 2] %= OID[u16Row].oidIndexMax[0];                           // include next value of index2
      tNxtOID[*u8NxtOIDLen - 2]++;
    }

    tNxtOID[*u8NxtOIDLen - 3] += bIncIdx3 == TRUE ? 1 : 0; // if rollover then include next
                                                           // value of index3 (column table)

  } else { // u8QtyIdx > 2
    printf("Error: OMNI does not use objects with 3 or more indices in oidIndexMax member \n");
  }

  return u16Row;
}

/*************************************************************************************************/
/*  Name       : snmp_getCommunityName                                                           */
/*                                                                                               */
/*  Description: copy the community name from the requests info structure to CommunityName       */
/*               buffer.                                                                         */
/*  Return     : none                                                                            */
/*                                                                                               */
/*************************************************************************************************/
void snmp_getCommunityName(netsnmp_request_info *reqinfo, char *CommunityName)
{
  strcpy(CommunityName, (char *)reqinfo->agent_req_info->asp->pdu->community);
}

/*************************************************************************************************/
/*  Name       : snmp_getRemoteIP                                                                */
/*                                                                                               */
/*  Description: copy the the IP address from the requests info structure to u32IpAddr.          */
/*                                                                                               */
/*  Return     : u32IpAddr, 32-bit value containing the remote IP address                        */
/*************************************************************************************************/
INT32U snmp_getRemoteIP(netsnmp_request_info *reqinfo)
{
  /* Port number start in the byte #4 (big-endian) */
  netsnmp_indexed_addr_pair *addr_pair = (netsnmp_indexed_addr_pair *)reqinfo->agent_req_info->asp->pdu->transport_data;
  netsnmp_sockaddr_storage *from = (netsnmp_sockaddr_storage *)&(addr_pair->remote_addr);
  INT32U u32IpAddr = from->sin.sin_addr.s_addr;

  return htonl(u32IpAddr);
}

/*************************************************************************************************/
/*  Name       : snmp_getRemotePort                                                              */
/*                                                                                               */
/*  Description: copy the Port number from the requests info structure to u16IpPort.             */
/*                                                                                               */
/*  Return     : u16IpPrt, 16-bit value containing the remote port number                        */
/*************************************************************************************************/
INT16U snmp_getRemotePort(netsnmp_request_info *reqinfo)
{
  netsnmp_indexed_addr_pair *addr_pair = (netsnmp_indexed_addr_pair *)reqinfo->agent_req_info->asp->pdu->transport_data;
  netsnmp_sockaddr_storage *from = (netsnmp_sockaddr_storage *)&(addr_pair->remote_addr);

  INT16U u16IpPort = from->sin.sin_port;

  return htons(u16IpPort);
}

/*************************************************************************************************/
/*  Name       : u8GetOidIndexCount                                                              */
/*                                                                                               */
/*  Description: Get the number of indexes from an OID entry row                                 */
/*    Returns the number of indexes if found, otherwise returns 0                                */
/*************************************************************************************************/
INT8U u8GetOidIndexCount(INT16U u16OidRow)
{
  INT8U u8Index = 0;

  for (u8Index = 0; u8Index < MA_MAX_OID_INDICES; u8Index++) {
    if (OID[u16OidRow].oidIndexMax[u8Index] == 0) {
      break;
    }
  }
  return u8Index;
}

/*************************************************************************************************/
/*  Name       : bIsOidNumeric                                                                   */
/*                                                                                               */
/*  Description: return TRUE if OID is a numeric object                                          */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN bIsOidNumeric(INT8U OMNItype)
{

  switch (OMNItype) {
    case OBJT_INT1:
    case OBJT_INT2:
    case OBJT_INT4:
    case OBJT_SIGN_INT1:
    case OBJT_SIGN_INT2:
    case OBJT_SIGN_INT4:
    case OBJT_COUNTER:
    case OBJT_GAUGE:
    case OBJT_TIME_TICKS:
    case OBJT_INT_UNRES:
      return TRUE;

    default:
      break;
  }

  return FALSE;
}

/*************************************************************************************************/
/*  Name       : u8GetOIDSize                                                                    */
/*                                                                                               */
/*  Description: Based on an OID type, returns how many bytes are required to store the data for */
/*               that same OID.                                                                  */
/*************************************************************************************************/
INT16U u16Get_OER_MaxSize(TYPE_OIDTABLE *tOID, BOOLEAN *bIsOctet, BOOLEAN *bIsNumeric)
{
  INT16U u16Tmp = 0;
  *bIsOctet = FALSE;
  *bIsNumeric = FALSE;

  switch (tOID->oidType) {
    case OBJT_INT1:
    case OBJT_SIGN_INT1:
      *bIsNumeric = TRUE;
      return 1;

    case OBJT_INT2:
    case OBJT_SIGN_INT2:
      *bIsNumeric = TRUE;
      return 2;

    case OBJT_COUNTER:
    case OBJT_GAUGE:
    case OBJT_TIME_TICKS:
    case OBJT_INT4:
    case OBJT_SIGN_INT4:
      *bIsNumeric = TRUE;
      return 4;

    case OBJT_INT_UNRES: // unrestricted integer includes one length octet, and may have up to 4 data octets
      *bIsNumeric = TRUE;
      return 5;

    case OBJT_OCTET:
    case OBJT_IP_ADDR:
    case OBJT_DISPLAY_STR:
    case OBJT_PHYS_ADDR:
    case OBJT_OWNER_STR:
    case OBJT_OID:
    case OBJT_OPAQUE:
      u16Tmp = tOID->oidMax;
      *bIsOctet = TRUE;
      return u8GetEncodedLength(u16Tmp) + u16Tmp; // else both Length and Value are encoded

    case OBJT_NULL:
      return 0;

    default:
      vMcSysLog(LOG_ERR, "unknown type");
      return 0;
  }

  return 0;
}

/*************************************************************************************************/
/*  Name       : vGetOIDTableMax                                                                 */
/*                                                                                               */
/*  Description: Loop thru the oid table to get the max.                                         */
/*               Only do this if we have not done so already.                                    */
/*                                                                                               */
/*************************************************************************************************/
void vGetOIDTableMax(void)
{
  INT16U u16Index = 0;

  // if (psATCsys->u16NumberOfOIDS != 0) {
  //   return; // Nothing to do here, already have the MAX OIDS.
  // }

  while (OID[u16Index].oidBaseIdx != -1) {
    u16Index++;
  }

  // psATCsys->u16NumberOfOIDS = u16Index;
  u16NumberOfOIDS = u16Index;
  // vMcSysLog(LOG_INFO, "Number of OIDs in the MIB are %d", psATCsys->u16NumberOfOIDS);
  //  printf("Max OID: %d\n", u16NumberOfOIDS);
}

/******************************************/
/* Function to debug only                 */
/******************************************/
void vDumpHex(INT8U *pu8Oct, INT16U len)
{
  int i = 0;
  for (i = 0; i < len; i++) {
    if (i % 16 == 0)
      printf("\n");
    printf("%02x ", pu8Oct[i]);
  }
  printf("\n");
}

/* End OIDTable.c */


# /*************************************************************************************************/
# /*                                              McCain                                           */
# /*                                        2365 Oak Ridge Way                                     */
# /*                                         Vista, CA 92081                                       */
# /*                                               USA                                             */
# /*                                          760-727-8100                                         */
# /*                                                                                               */
# /*                                           Copyright (c)                                       */
# /*                                                                                               */
# /*  All rights reserved. This McCain, Inc. source code is an unpublished work and the use of a   */
# /*  copyright notice does not imply otherwise. This source code contains confidential, trade     */
# /*  secret material of McCain, Inc. Any attempt or participation in deciphering, decoding,       */
# /*  reverse engineering or in any way altering the source code is strictly prohibited, unless    */
# /*  the prior written consent of McCain, Inc is obtained.                                        */
# /*                                                                                               */
# /*  Description: This file contains the declaration of the all OIDs used and implemented in OMNI */
# /*                                                                                               */
# /*************************************************************************************************/

from Framework.ASN import *

#
#---------- ITS Cabinet SDLC I/O to SIU's ----------
RMC_MAX_ITS_DEVICES = "1.3.6.1.4.1.1206.3.21.3.2.7.1.0"
MAX_ITS_DEVICES = "1.3.6.1.4.1.1206.3.21.2.2.7.1.0"     # addresses 0-20, SIUs in range 0-14, CMU is address 15, FIO is address 20 (see ITS Cabinet Standard v01.02.17b sections 4.7.14.7.1 and 6.1.3.2)
NUM_ITS_SIUS = 15        # include all possible SIU addresses 0-14 so we can use the address as an array index
NUM_ITS_SIU_INPUTS =  58  # each SIU has 58 possible inputs (54 I/O, 4 optical)
NUM_ITS_SIU_OUTPUTS = 54 # each SIU has 54 possible outputs (54 I/O pins) I/O pins used as inputs must be set to zero

#---------- LOGIC I/O (combination logic on I/O) ----------
NUM_IOLOGIC_GATE_INPUTS = 4
NUM_IOLOGIC_GATES = 64

#---------- OMNI_TSP_OPTIONS ----------
OMNI_TSP_OPTIONS_ENABLE = 0x01   # Mask to get the enable option 
OMNI_TSP_OPTIONS_OVERRIDE = 0x02 # Mask to get the override option 

#---------- OVERLAPS ----------
MAX_OVERLAPS = 16               # maxOverlaps
MAX_VEH_OVERLAPS = MAX_OVERLAPS # Maximum vehicle overlaps.
MAX_PED_OVERLAPS = MAX_OVERLAPS # maxPedOverlaps (----- McCain custom objects -----)

#---------- PHASES ----------
MAX_PHASES = 16                     # maxPhases
PHASE_LIST_SIZE = 16                # max entries in a phase concurrency list (phaseConcurrency)
HALF_THE_PHASES = (MAX_PHASES >> 1) # The half of the maximum number of phases

#---------- PEER INPUTS ----------
NUM_PEER_INPUTS = 8
NUM_PEER_INPUT_FUNCTIONS = 32

#---------- PREEMPTS ----------
MAX_PREEMPTS = 16 # maxPreempts

#---------- MAX PREEMPT GROUPS----------
MAX_PREEMPT_GROUPS = 2

# ----- Reports -----
NUM_EVENTCLASSES = 8
NUM_EVENTLOGCONFIGS = 60
SIZE_EVTCFGCOMPOID = 20 # eventConfigCompareOID
SIZE_EVTCFGLOGOID = 20  # eventConfigLogOID
SIZE_EVTCLASSDESCR = 50 # eventClassDescription

#---------- RINGS ----------
MAX_RINGS = 4           # maxRings
MAX_BARRIERS = 16       # maxBarriers
MAX_SEQUENCES = 16      # maxSequences
RING_SEQUENCE_SIZE = 16 # max entries in a ring sequence (sequenceData)

#---------- RS232 PORTS ----------
NUM_RS232PORTS = 8 # Number of RS232/RS485 ports in system (both ASYNC and SYNC)
MAX_PMPP_ADDRESS = 8192         # Valid 2-byte address range is 1-8191, 8192 is used as special case meaning respond to any address
MAX_PMPP_GROUP_ADDRESS = 62     # Only suppoting 1-byte group addresses, valid range is 1-62
ALL_STATIONS_GROUP_ADDRESS = 63 # Reserved group address for all stations

#---------- Ethernet PORTS ----------
MAX_ETHERNET_PORT_NUMBER = 0xFFFF # Maximu number for an ethernet port
MAX_ETHERNET_FHP_CITY_CODE = 127  # Maximum code number of Foothill protocol city code

#Maximum values for NTP Interval time.
INTERVAL_HOUR_LIMIT = 24
INTERVAL_MINUTE_LIMIT = 59


# ----- Menu Permissions node -----
NUM_PERMISSIONS_USERS = 64 # Maximum number of users and pins (menu permissions).

# ---- Comunity node -----
MAX_COMMUNITYNAMES = 8  # max number of non-admin community names
SIZE_CMTYNAMEADMIN = 16 # size_communityNameAdmin
SIZE_CMTYNAMEUSER = 16  # size_communityNameUser

# ----- Security node -----
MAX_SECURITY_USERS = 8 # Maximum number of users
SIZE_USERNAME = 32     # Includes the NULL terminating character.
MAX_SIZE_USERNAME = SIZE_USERNAME
MIN_SIZE_USERNAME = 4
SIZE_SALT = 8
SIZE_USERKEY = 28              # fixed size, non NULL terminated octet string. 20 octets plus SIZE_SALT.
SIZE_OCTET_STRING_CONFIG = 253 # 255 - LOCAL_OCTET_HEADER_SIZE.

#---------- SDLC I/O (2070-2A FIO) ----------
NUM_2070_2A_INBYTES = 8   # 8 bytes of inputs for the 2070-2A FIO adapter
NUM_2070_2A_OUTBYTES = 8  # 8 bytes of outputs for the 2070-2A FIO adapter


#---------- SDLC I/O (2070-2A FIO) ----------
NUM_2070_2A_INBITS = (NUM_2070_2A_INBYTES * 8)   # 64 bits of inputs for the 2070-2A FIO adapter
NUM_2070_2A_OUTBITS = (NUM_2070_2A_OUTBYTES * 8) # 64 bits of outputs for the 2070-2A FIO adapter

#---------- SIZES OF TABLES FOR PARAMETER SETS ----------
MAX_DETECTOR_TABLES = 4 # number of sets of detector parameter tables, and det diagnostic parameter tables
MAX_PHASE_TABLES = 4    # number of sets of phase parameter tables, and phase options tables
MAX_OVERLAP_TABLES = 4  # number of sets of overlap parameter tables, and ped overlap parameter tables
MAX_TSP_TABLES = 4      # number of sets of TSP parameter tables

#---------- DETECTORS ----------
MAX_DETECTORS = 128    # maxVehicleDetectors
MAX_PED_DETECTORS = 16 # maxPedestrianDetectors

#---------- DETECTORS ----------
MAX_DETGROUPS = ((MAX_DETECTORS + 7) / 8) # maxVehicleDetectorStatusGroups

#---------- PED DETECTORS ----------
MSK_ALLPEDDETS = 0xFFFF                       # bitmask for all ped detectors
MAX_PEDGROUPS = ((MAX_PED_DETECTORS + 7) / 8) # maxPedestrianDetectorGroups

#---------- ALARM INPUTS ----------
MAX_ALARM_INPUTS = 16                          # max number of alarm inputs, no NTCIP object for this
MAX_ALARMGROUPS = ((MAX_ALARM_INPUTS + 7) / 8) # maxAlarmGroups

#---------- SPECIAL FUNCTION I/O ----------
MAX_SPECIALFUNCS = 16 # maxSpecialFunctionOutputs


#---------- DETECTOR LOGGING ----------
MAX_SPEED_BINS = 16  # number of speed bins that can be stored in the speed log
MAX_SPEED_TRAPS = 16 # number of speed traps that can be set up

CTLR_LOG_ENTRY_DATA_LEN = 40 #the length of a controller log entry in bytes
SIZE_CNTRL_LOG_ROW = 49 # size of one log entry (see MIB):  40 bytes message, 4 bytes timestamp, 4 bytes sequence number and 1 byte for log type (used in OIDtable.c)

NUM_CNTRL_LOG_OPERATOR_EVENTS = 300
NUM_CNTRL_LOG_ACCESS_EVENTS = 300
NUM_CNTRL_LOG_COMMAND_EVENTS = 300
NUM_CNTRL_LOG_COMM_EVENTS = 300
NUM_CNTRL_LOG_DETECTOR_EVENTS = 300
NUM_CNTRL_LOG_PREEMPT_EVENTS = 300
NUM_CNTRL_LOG_TSP_EVENTS = 300
NUM_CNTRL_LOG_EVENTS = (NUM_CNTRL_LOG_OPERATOR_EVENTS + NUM_CNTRL_LOG_ACCESS_EVENTS + NUM_CNTRL_LOG_COMMAND_EVENTS +
                        NUM_CNTRL_LOG_COMM_EVENTS + NUM_CNTRL_LOG_DETECTOR_EVENTS + NUM_CNTRL_LOG_PREEMPT_EVENTS +  
                        NUM_CNTRL_LOG_TSP_EVENTS)

# ---------- SPaT destinations ----------
MAX_SPAT_DESTINATIONS = 4

#----- Dynamic Object data sizes -----
MAX_DYNOBJ_VARS = 128  # max number of variables that may be stored for each dynamic object
MAX_DYNOBJS = 13       # number of dynamic objects (limited to 13 by NTCIP protocol)
SIZE_DYNCFG_OWNER = 50 # max chars allowed in dynObjConfigOwner
SIZE_DYNOBJ_VAR = 20   # max number of octets in a dynamic object OID entry

#-- MAX values for database and buffers to hold largest type, leave room for future expansion
MAX_NEMA_INBYTES = 24  # max number supported in database, exceeds number currently used
MAX_NEMA_OUTBYTES = 24 # max number supported in database, exceeds number currently used
NUM_NEMA_INBYTES = 15  # number of bytes currently used for largest NEMA I/O device (2070N, Traconex)
NUM_NEMA_OUTBYTES = 16 # number of bytes currently used for largest NEMA I/O device (820A)
NUM_NEMA_INBITS = (NUM_NEMA_INBYTES * 8)
NUM_NEMA_OUTBITS = (NUM_NEMA_OUTBYTES * 8)
NEMA_IOSTR_SIZE = 16 # I/O pin orginal func, 16 chars, ex: "A-FF PED RECY R1", this length does NOT include a zero terminator

IOI_NUMIDS = 86
IOO_NUMIDS = 34
NUM_TS2_BIUS = '.1.3.6.1.4.1.1206.3.21.2.2.4.1'
NUM_TS2_BIU_INPUTS = '.1.3.6.1.4.1.1206.3.21.2.2.4.2'
NUM_TS2_BIU_OUTPUTS = '.1.3.6.1.4.1.1206.3.21.2.2.4.4'
RM_NUM_TS2_BIUS = "1.3.6.1.4.1.1206.3.21.3.2.4.1.0"
RM_NUM_TS2_BIU_INPUTS = "1.3.6.1.4.1.1206.3.21.3.2.4.2.0"
RM_NUM_TS2_BIU_OUTPUTS = "1.3.6.1.4.1.1206.3.21.2.2.4.4.0"
IOGO_NUMIDS = 58
IOGI_NUMIDS = 90

ADJUSTMENT_ABSOLUTE = 1
ADJUSTMENT_PERCENTAGE = 2
ADJUSTMENT_DELTA = 3
ADJUSTMENT_MAX = ADJUSTMENT_DELTA

# === COORD SPLIT MODES ===============================
SPLIT_MODE_OTHER = 1 # splitMode
SPLIT_MODE_NONE = 2
SPLIT_MODE_MIN_VEH_RECALL = 3
SPLIT_MODE_MAX_VEH_RECALL = 4
SPLIT_MODE_PED_RECALL = 5
SPLIT_MODE_MAX_VEH_AND_PED_RECALL = 6
SPLIT_MODE_PHASE_OMITTED = 7
SPLIT_MODE_NONACT = 8 #custom value

#---------- COORDINATION RESERVICE ----------
MAX_RESERVICE_COUNT_LIMIT = 5

# === COORD INCLUDE PEDS MODES =======================
COORD_INC_PEDS_UNIT = 1 # mcAtcCoordCoverPeds, mcAtcPatternCoverPeds
COORD_INC_PEDS_PEDCALLS = 2
COORD_INC_PEDS_ALLPEDS = 3

# === COORD YIELD STRATEGY MODES =======================
COORD_YIELD_UNIT = 1 # mcAtcCoordYieldStrategy, mcAtcPatternYieldStrategy
COORD_YIELD_STANDARD = 2
COORD_YIELD_ALLPERM = 3

# Values for u8TspRejectionCode
TSP_REJECT_NOT_REJECTED = 0 # The TSP request adjustments were not rejected

# Added TSP status to be used with mcAtcPriorityState (Not part of the TSP state machine)
TSP_STATE_NOT_ACTIVE = 1
TSP_STATE_ACTIVE_NO_ACTION = 2
TSP_STATE_SP_GREEN_EXTENSION = 3
TSP_STATE_NON_SP_GREEN_EXTENDED = 4
TSP_STATE_NO_ADJUSTMENT_PREEMPT = 6
TSP_STATE_HEADWAY_TIMER_ACTIVE = 8       # Set when only headway timer is active.
TSP_STATE_LOCKOUT_ACTIVE = 9             # Set when only preempt lockout timer is active.
TSP_STATE_PREEMPT_HEADWAY_ACTIVE = 10    # Set when both headway timer and preempt lockout timer are active
TSP_STATE_SP_GREEN_REDUCTION = 11        # Set when service phase is active and is being reduced
TSP_STATE_SP_GREEN_NO_CHANGE = 12        # Set when service phase is active and is not being extended nor reduced
TSP_STATE_NON_SP_GREEN_REDUCED = 13      # Set when a non-service phase is active and is being reduced
TSP_STATE_NON_SP_GREEN_NO_CHANGE = 14    # Set when a non-service phase is active and is not being extended nor reduced
TSP_STATE_USING_ARRIVAL_WINDOW = 15      # Should be last state. Add new states before this one.
TSP_STATE_NO_ADJUSTMENT_CYCLE_FAULT = 16 # Should that have really been the last state? this follows mib enum
TSP_STATE_MAX_STATE = TSP_STATE_NO_ADJUSTMENT_CYCLE_FAULT

# Values for mcAtcPriorityStrategyState
TSP_STRAT_STATE_NOT_ACTIVE = 1
TSP_STRAT_STATE_NOT_ACTIVE_WITH_CALL = 2
TSP_STRAT_STATE_ETA_STARTED = 3
TSP_STRAT_STATE_HEADWAY_TIMER_ACTIVE = 4
TSP_STRAT_STATE_PREEMPT_LOCKOUT_ACTIVE = 5
TSP_STRAT_STATE_PREEMPT_HEADWAY_ACTIVE = 6
TSP_STRAT_STATE_DELAY_TIMER_ACTIVE = 7
TSP_STRAT_STATE_EXTEND_TIMER_ACTIVE = 8
TSP_STRAT_STATE_SP_GREEN_EXTENSION = 9
TSP_STRAT_STATE_SP_GREEN_REDUCTION = 10
TSP_STRAT_STATE_SP_GREEN_NO_CHANGE = 11
TSP_STRAT_STATE_NON_SP_GREEN_EXTENDED = 12
TSP_STRAT_STATE_NON_SP_GREEN_REDUCED = 13
TSP_STRAT_STATE_NON_SP_GREEN_NO_CHANGE = 14
TSP_STRAT_STATE_REQUEST_TIMER_EXPIRED = 15 # Should be last state. Add new states before this one.
TSP_STRAT_STATE_MAX_STATE = TSP_STRAT_STATE_REQUEST_TIMER_EXPIRED

# Values for mcAtcPriorityStrategyInputState
TSP_STRAT_IN_STATE_NOT_ACTIVE = 1
TSP_STRAT_IN_STATE_IN_ACTIVE_STEADY = 2
TSP_STRAT_IN_STATE_IN_ACTIVE_PULSING = 3
TSP_STRAT_IN_STATE_CHECKOUT_ACTIVE = 4
TSP_STRAT_IN_STATE_CHECKOUT_ACTIVE_IN_STEADY = 5
TSP_STRAT_IN_STATE_CHECKOUT_ACTIVE_IN_PULSING = 6
TSP_STRAT_IN_STATE_MAX_PRESENCE_EXPIRED = 7
TSP_STRAT_IN_STATE_MAX_PRESENCE_CLEAR_ACTIVE = 8
TSP_STRAT_IN_STATE_TPRG_ACTIVE = 9
TSP_STRAT_IN_STATE_CHECKOUT_ACTIVE_TPRG_ACTIVE = 10  # Should be last state. Add new states before this one.
TSP_STATE_IN_MAX_STATE = TSP_STRAT_IN_STATE_CHECKOUT_ACTIVE_TPRG_ACTIVE

#*************************************************************************************************/
#*                                   Miscellaneous Constants                                     */
#*************************************************************************************************/
MAX_RLP_ACTIVATIONS_PER_CYCLE = 24
MAX_RLP_CYCLE_HEADWAY = 60

# === EXIT AUTO FLASH ALL RED ENABLE MODES ===========
EXIT_AUTO_FLASH_ALL_RED_DISABLED = 1
EXIT_AUTO_FLASH_ALL_RED_ENABLED = 2
EXIT_AUTO_FLASH_ALL_RED_MIN = 1
EXIT_AUTO_FLASH_ALL_RED_MAX = 100

#---------- CHANNELS ----------
MAX_CHANNELS = 32     # maxChannels
MAX_MMU_CHANNELS = 32 # mcAtcMMUchannels - number of channels the MMU monitors and feeds back to us (16 channels used for TS2 MMU, 32 used for ITS CMU)

#---------- COORDINATION ----------
MAX_PATTERNS = 250     # maxPatterns
MAX_SPLITS = 250       # maxSplits (number of split plans)
DEFAULT_SET_INDEX = 0  # default to using set 1 (index 0) in free/flash plans
DEFAULT_MAX_PHASES = 0 # default to use in free/flash plans
DEFAULT_DET_RESET = 0  # no detector reset by default

# ----- Daylight savings -----
MAX_DST_ENTRIES = 96 # 1 per year from 1970 if absolute method. At least one entry is needed to use month/week/DOW method
MIN_TZ_OFFSET = -43200
MAX_TZ_OFFSET = 43200
MAX_DST_SECONDS = 21600

SECS_PER_HOUR = 3600
SECS_PER_DAY = (SECS_PER_HOUR * 24)

MCCAIN_EVENTS_COUNT = 218

HIRES_FILE_FORMAT_VER_1 = 1 # Log file format version, increment if header or event record structure is changed
HIRES_FILE_FORMAT_VER_2 = 2
HIRES_SYSNAME_SIZE = 32       # Size of sysName string in file header
HIRES_DESCRIPTION_LENGTH = 60 # Max length allowed to descript an event

# Old defines -these files have a strong dependency on menu process
HIRES_MAX_CLOCK_DELTA = 127 # Largest magnitude of clock difference that can be reported in Clock Updated event parameter, range = (-HIRES_MAX_CLOCK_DELTA, +HIRES_MAX_CLOCK_DELTA)

#---------- TS2 PORT1 ----------
MAX_PORT1_DEVICES = 19 # TS2 Port1 devices for addresses 0-18

# -- Boston.
MAX_BOSTON_SETTINGS = 8
BOSTON_UTCS_IN_BUFFER_LENGTH = 4
BOSTON_UTCS_OUT_BUFFER_LENGTH = 8

MAX_OCTET_LENGTH = 1024 
SIZE_ASCBLKGETCTRL = 12 # max size of ascBlockGetControl data
SIZE_ASCBLOCKDATA = MAX_OCTET_LENGTH # Block payload is an octet string, so use same size as MAX_OCTET_LENGTH. 

# definitions of maximum sub nodes
MAX_MCCAIN_MIB_SUBNODES = 30
MAX_MCCAIN_RAMPMETER_MIB_SUBNODES = 30
MAX_MAINLINE_LANES = '1.3.6.1.4.1.1206.4.2.2.2.2.0' # from Ramp Meter defines values

NUM_STD_RAMP_ASC_BLKS = '1.3.6.1.4.1.1206.3.21.3.3.1.0'
NUM_CUSTOM_RAMP_ASC_BLKS = '1.3.6.1.4.1.1206.3.21.3.3.3.0'
MAX_RAMP_AUX_OUTPUTS = '1.3.6.1.4.1.1206.3.21.3.4.1.0'
MAX_QUEUES = '1.3.6.1.4.1.1206.3.21.3.5.1.0'
# definitions of maximum ramp meter
MAX_METERING_LANES = 6

GLOBMOD_LAST = 5
MAX_GLOBALMODULES = GLOBMOD_LAST # define table size from enum list
SIZE_GLOBALMOD_STR = 68

MAX_DST_VALUE = 20

#---------- TBC ----------
SIZE_ACTIONOID = 16 # size_dayPlanActionNumberOID

DST_OCCURRENCES_FIRST = 1
DST_OCCURRENCES_SPECIFIC_DAY_OF_MONTH = 9
SUNDAY = 1
SATURDAY = 7
DST_MONTH_JAN = 1
DST_MONTH_DEC = 12

EVENTMODEOTHER = 1
EVENTMODEANDEDWITHVALUE = 7

# values for eventConfigAction
EVENTACTIONOTHER = 1
#EVENTACTIONDISABLED = 2
EVENTACTIONLOG = 3

#values for eventConfigStatus
EVENTSTATUSOTHER = 1
# EVENTSTATUSDISABLED = 2
# EVENTSTATUSLOG = 3
EVENTSTATUSERROR = 4


# ---- OID Database configuration ----------------------------------------------
LEN_OID_FIXED = 3 # fixed length preamble that all OID's start with
LEN_OID_BASE = 2  # a "base" of octets common to a group of OID's
NUM_OID_BASE = 2  # number of different base groups
LEN_OID_PART = 10 # maximum number of unique octets stored for an OID


# ----- Reports -----
SIZE_EVENTLOGVALUE = 12 # eventLogValue
NUM_EVENTLOGS = 800
SIZE_REPOBJ_OID = (LEN_OID_FIXED + LEN_OID_BASE + LEN_OID_PART + 4) # add 2 + 2 for large first and second indexes

NUM_STD_ASC_BLKS = 54
NUM_CUSTOM_ASC_BLKS = 108
SIZE_TABLE_DEF_BUFFER = 20                                         # Size of the table definition single response buffer (OID octet + type + value size) */
MAX_TABLE_ROWS = (256 * 16)                                        # The multiplication of two indexes (p.i. splits * phases)
MAX_TABLE_ENTRIES = 50                                             # Max number of entries for each block table
MAX_BLOCK_DEFINITION = (SIZE_TABLE_DEF_BUFFER * MAX_TABLE_ENTRIES) # Max number of bytes for an octet encoded string

DOWFUNC_NUMFUNCTIONS = 38

MAX_OID_INDICES = 4    # Maximum number of OID indices for the object being referenced.
SIZE_COMMSBLOCK = 1472 # Size of the message block in each comms message buffer.

#*************************************************************************************************/
#*   Extended TSP data sizes                                                                     */
#*************************************************************************************************/
PRIORITY_IMAGE_MAX_ENTRIES = 30
PRIORITY_IMAGE_MAX_IMAGES = 9
PRIORITY_IMAGE_MAX_SIZE = 900
PRIORITY_IMAGE_NAME_MAX = 15

#---------- Ethernet PORTS ----------
NUM_ETHERNETPORTS = 2  # Number of Ethernet ports supported
SIZE_IPv6_ADDRESS = 16 # the size of an IPv6 address
SIZE_HOSTNAME = 50     # max chars allowed in mcAtcEthernetHostname
MAX_FHP_FORWARDS = 4   # Maximum number of Foothill Protocol response forward locations


NUM_IFS = NUM_ETHERNETPORTS # number of Ethernet interfaces (allow more for PPP connections?)
SIZE_IFDESCR = 255
NUM_IPADDRS = NUM_IFS  # From the RFC1213 spec: these index objects refer to the same interfaces
NUM_IPROUTES = NUM_IFS # as ifIndex and so must be the same size
NUM_IPNETTOMEDIAS = NUM_IFS
NUM_TCPCONNS = 16
NUM_UDPS = 16

NUM_LOGNAMETRANS = NUM_IFS # NUM_LOGICALNAMETRANSLATIONS
SIZE_LOGNAMETRANS = 32     # size_logicalNameTranslationlogicalName

# --------- HDLC ----------
NUM_HDLCGRPADDR = (NUM_RS232PORTS + NUM_ETHERNETPORTS) #NUM_HDLCGROUPADDRESSS (maps 1-to-1 to serial ports, then to Ethernet ports)

#---------- PHASES ----------
PHASEGROUP_SIZE = 8                                                      # Size of each phase group
MAX_PHASEGROUPS = ((MAX_PHASES + PHASEGROUP_SIZE - 1) / PHASEGROUP_SIZE) # maxPhaseGroups

#---------- RINGS ----------
MAX_RINGGROUPS = ((MAX_RINGS + 7) / 8) # maxRingControlGroups

#---------- CHANNELS ----------
MAX_CHANGROUPS = ((MAX_CHANNELS + 7) / 8) # maxChannelStatusGroups

#---------- OVERLAPS ----------
MAX_OVERLAP_GROUPS = ((MAX_VEH_OVERLAPS + 7) / 8) # maxOverlapStatusGroups


# ----- System group RFC 1213 -----
SIZE_SYSCONTACT = 255
SIZE_SYSNAME = 255
SIZE_SYSLOCATION = 255
SIZE_SYSDESCR = 255
SIZE_SYSNAME = 255
SIZE_SYSLOCATION = 255


#---------- TBC ----------
MAX_TBC_ACTIONS = 250  # maxTimebaseAscActions
MAX_TBC_DAYPLANS = 64  # maxDayPlans
MAX_TBC_EVENTS = 48    # maxDayPlanEvents
MAX_TBC_SCHEDULES = 64 # maxTimeBaseScheduleEntries

#---------- TSP - Transit Signal Priority ----------
MAX_TSP_STRATEGIES = 16   # NTCIP 1211 priorityStrategiesMax
SIZE_TSP_GNODE_NAME = 30  # max length of mcAtcPriorityGlobalNodeName
SIZE_TSP_STRAT_DESCR = 40 # max length of mcAtcPriorityStrategyDescription

#---------- Day of Week ----------
MAX_DOW_SCHEDULES = 16          # Max DOW Schedules supported
MAX_DOW_FUNCTION_SETS = 16      # Max DOW Function Sets
MAX_DOW_FUNCTION_BYTES = 2      # Max amount of bytes to represent a function value
MAX_DOW_FUNCTION_OCTET_LEN = 32 # Max Octet length for mcAtcDOWFunctions
MAX_DOW_FUNCTION_VALUES_OCTET_LEN = MAX_DOW_FUNCTION_OCTET_LEN * MAX_DOW_FUNCTION_BYTES  # Max Octet length for mcAtcDOWFunctionValues (mcAtcDOWFunctions Max Length * Max amount of bytes to represent a function value)
OWFUNC_NUMFUNCTIONS = 38

#---------- DETECTOR LOGGING ----------
MAX_VOS_COMBINED_PERIODS = 255                     # mcAtcDetVOSLogCombinedPeriods (max number of VOL/OCC periods that may be combined into one det vol/occ log entry)
MAX_LOG_DETS = 32                                  # mcAtcMaxLogDetectors (max number of volume/occupancy detectors that may be logged)
MAX_VOS_LOGS = 1000                                # maximum number of entries in the det VOL/OCC log file
SIZE_VOS_ROW = (12 + (6 * 32))										 # Maximum size for mcAtcDetVOSLogEntryData
#FN_DET_VOS_LOG = BSD_LOG_FILES + "/" + BN_DET_VOS_LOG  # file name for the detector volume/occupancy log
#WFN_DET_VOS_LOG = BWD_LOG_FILES + "/" + BN_DET_VOS_LOG # Working file name for the detector volume/occupancy log (used by the log generator)
VOS_LOG_VER = 1                                    # version number of the current log file
VOS_LOG_DESCRIPTOR = "VOS LOG"                     # Descriptor for the VOS log (put into header)

MAX_SPD_LOGS = 1000                                # maximum number of entries in the det speed log file
SIZE_SPEED_ROW = (12 + (18 * 16))									 # Maximum size for mcAtcSpeedTrapLogEntryData
#FN_DET_SPD_LOG = BSD_LOG_FILES + "/" + BN_DET_SPD_LOG  # file name for the detector speed log
#WFN_DET_SPD_LOG = BWD_LOG_FILES + "/" + BN_DET_SPD_LOG # Working file name for the detector speed log (used by the log generator)
SPD_LOG_VER = 1                                    # version number of the current log file
SPD_LOG_DESCRIPTOR = "SPD LOG"                     # Description for the SPD log (put into header)

#---------- ACTIVITY/EVENTS LOGGING ----------
#CTLR_LOG_ATC_PATH = BSD_LOG_FILES + "/" + BN_CTLR_LOG   # path for the controller log on the atc
#W_CTLR_LOG_ATC_PATH = BWD_LOG_FILES + "/" + BN_CTLR_LOG # path for the working controller log on the atc

#---------- MOE LOGGING -----------
MAX_MOE_LOGS = 1000                                # maximum number of entries in the cycle MOE log file
SIZE_MOE_ROW = ((3 * 16) + 12)										 # Maximum size for mcAtcCycleMOELogEntryData
#FN_CYC_MOE_LOG = BSD_LOG_FILES + "/" + BN_CYC_MOE_LOG  # file name for the cycle MOE log
#WFN_CYC_MOE_LOG = BWD_LOG_FILES + "/" + BN_CYC_MOE_LOG # Working file name for the cycle MOE log (used by the log generator)
MOE_LOG_VER = 1                                    # version number of the current log file
MOE_LOG_DESCRIPTOR = "MOE LOG"                     # Descriptor for the MOE log (put into header)

#---------- LOG MODES -----------
LOG_MODE_DISABLED = 1 # mcAtcDetVOSLogMode, mcAtcSpeedTrapLogMode, mcAtcCycleMOELogMode
LOG_MODE_ENABLED = 2
LOG_MODE_TIMEBASE = 3

LOG_MODE_TIMEBASE_NOACTION = 1 # mcAtcTimebaseDetVOSLog, mcAtcTimebaseSpeedTrapLog, mcAtcTimebaseCycleMOELog
LOG_MODE_TIMEBASE_START = 2
LOG_MODE_TIMEBASE_STOP = 3

#---------- LOG OPTIONS -----------            # mcAtcLogOptions
LOG_OPT_DISPLAY_METRIC = 0x01 # display speed/length values using metric units. If not enabled then English units will be used.

OIDTable = { 
    # System - RFC 1213
		'1.3.6.1.2.1.1.1.0' : [ (0,0,0,0), ACCESS_RD, (0, SIZE_SYSDESCR), ASN_OCTET_STR, "sysDescr", "mandatory" ],
		'1.3.6.1.2.1.1.2.0' : [ (0,0,0,0), ACCESS_RD, (0, 50), ASN_OBJECT_ID, "sysObjectID", "mandatory" ],
		'1.3.6.1.2.1.1.3.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_TIMETICKS, "sysUpTime", "mandatory" ],
		'1.3.6.1.2.1.1.4.0' : [ (0,0,0,0), ACCESS_P, (0, SIZE_SYSCONTACT), ASN_OCTET_STR, "sysContact", "mandatory" ],
		'1.3.6.1.2.1.1.5.0' : [ (0,0,0,0), ACCESS_P, (0, SIZE_SYSNAME), ASN_OCTET_STR, "sysName", "mandatory" ],
		'1.3.6.1.2.1.1.6.0' : [ (0,0,0,0), ACCESS_P, (0, SIZE_SYSLOCATION), ASN_OCTET_STR, "sysLocation", "mandatory" ],
		'1.3.6.1.2.1.1.7.0' : [ (0,0,0,0), ACCESS_RD, (0, 127), ASN_INTEGER, "sysServices", "mandatory" ],
		
    # Interface - RFC 1213		
		'1.3.6.1.2.1.2.1.0' : [ (0,0,0,0), ACCESS_RD, (0, 2), ASN_UNSIGNED, "ifNumber", "mandatory" ],
		
		'1.3.6.1.2.1.2.2.1.1.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_UNSIGNED, "ifIndex", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.2.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, SIZE_IFDESCR), ASN_OCTET_STR, "ifDescr", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.3.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "ifType", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.4.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_UNSIGNED, "ifMtu", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.5.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_GAUGE, "ifSpeed", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.6.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_OCTET_STR, "ifPhysAddress", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.7.0' : [ (NUM_IFS,0,0,0), ACCESS_RW, (1, 3), ASN_INTEGER, "ifAdminStatus", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.8.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "ifOperStatus", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.9.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_TIMETICKS, "ifLastChange", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.10.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ifInOctets", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.11.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ifInUcastPkts", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.12.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ifInNUcastPkts", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.13.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ifInDiscards", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.14.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ifInErrors", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.15.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ifInUnknownProtos", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.16.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ifOutOctets", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.17.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ifOutUcastPkts", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.18.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ifOutNUcastPkts", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.19.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ifOutDiscards", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.20.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ifOutErrors", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.21.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_GAUGE, "ifOutQLen", "mandatory" ],
		'1.3.6.1.2.1.2.2.1.22.0' : [ (NUM_IFS,0,0,0), ACCESS_RD, (0, 50), ASN_OBJECT_ID, "ifSpecific", "mandatory" ],
		
    # IP  -  RFC 1213		
		'1.3.6.1.2.1.4.1.0' : [ (0,0,0,0), ACCESS_RW, (1, 2), ASN_INTEGER, "ipForwarding", "mandatory" ],
		'1.3.6.1.2.1.4.2.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_UNSIGNED, "ipDefaultTTL", "mandatory" ],
		'1.3.6.1.2.1.4.3.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipInReceives", "mandatory" ],
		'1.3.6.1.2.1.4.4.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipInHdrErrors", "mandatory" ],
		'1.3.6.1.2.1.4.5.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipInAddrErrors", "mandatory" ],
		'1.3.6.1.2.1.4.6.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipForwDatagrams", "mandatory" ],
		'1.3.6.1.2.1.4.7.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipInUnknownProtos", "mandatory" ],
		'1.3.6.1.2.1.4.8.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipInDiscards", "mandatory" ],
		'1.3.6.1.2.1.4.9.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipInDelivers", "mandatory" ],
		'1.3.6.1.2.1.4.10.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipOutRequests", "mandatory" ],
		'1.3.6.1.2.1.4.11.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipOutDiscards", "mandatory" ],
		'1.3.6.1.2.1.4.12.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipOutNoRoutes", "mandatory" ],
		'1.3.6.1.2.1.4.13.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_UNSIGNED, "ipReasmTimeout", "mandatory" ],
		'1.3.6.1.2.1.4.14.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipReasmReqds", "mandatory" ],
		'1.3.6.1.2.1.4.15.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipReasmOKs", "mandatory" ],
		'1.3.6.1.2.1.4.16.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipReasmFails", "mandatory" ],
		'1.3.6.1.2.1.4.17.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipFragOKs", "mandatory" ],
		'1.3.6.1.2.1.4.18.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipFragFails", "mandatory" ],
		'1.3.6.1.2.1.4.19.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipFragCreates", "mandatory" ],
		
		'1.3.6.1.2.1.4.20.1.1.0' : [ (NUM_IPADDRS,0,0,0), ACCESS_RD, (4, 4), ASN_IPADDRESS, "ipAdEntAddr", "mandatory" ],
		'1.3.6.1.2.1.4.20.1.2.0' : [ (NUM_IPADDRS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_UNSIGNED, "ipAdEntIfIndex", "mandatory" ],
		'1.3.6.1.2.1.4.20.1.3.0' : [ (NUM_IPADDRS,0,0,0), ACCESS_RD, (4, 4), ASN_IPADDRESS, "ipAdEntNetMask", "mandatory" ],
		'1.3.6.1.2.1.4.20.1.4.0' : [ (NUM_IPADDRS,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_UNSIGNED, "ipAdEntBcastAddr", "mandatory" ],
		'1.3.6.1.2.1.4.20.1.5.0' : [ (NUM_IPADDRS,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "ipAdEntReasmMaxSize", "mandatory" ],
		
		'1.3.6.1.2.1.4.21.1.1.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RW, (4, 4), ASN_IPADDRESS, "ipRouteDest", "mandatory" ],
		'1.3.6.1.2.1.4.21.1.2.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_UNSIGNED, "ipRouteIfIndex", "mandatory" ],
		'1.3.6.1.2.1.4.21.1.3.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_UNSIGNED, "ipRouteMetric1", "mandatory" ],
		'1.3.6.1.2.1.4.21.1.4.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_UNSIGNED, "ipRouteMetric2", "mandatory" ],
		'1.3.6.1.2.1.4.21.1.5.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_UNSIGNED, "ipRouteMetric3", "mandatory" ],
		'1.3.6.1.2.1.4.21.1.6.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_UNSIGNED, "ipRouteMetric4", "mandatory" ],
		'1.3.6.1.2.1.4.21.1.7.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RW, (4, 4), ASN_IPADDRESS, "ipRouteNextHop", "mandatory" ],
		'1.3.6.1.2.1.4.21.1.8.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RW, (1, 4), ASN_INTEGER, "ipRouteType", "mandatory" ],
		'1.3.6.1.2.1.4.21.1.9.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "ipRouteProto", "mandatory" ],
		'1.3.6.1.2.1.4.21.1.10.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_UNSIGNED, "ipRouteAge", "mandatory" ],
		'1.3.6.1.2.1.4.21.1.11.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RW, (4, 4), ASN_IPADDRESS, "ipRouteMask", "mandatory" ],
		'1.3.6.1.2.1.4.21.1.12.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_UNSIGNED, "ipRouteMetric5", "mandatory" ],
		'1.3.6.1.2.1.4.21.1.13.0' : [ (NUM_IPROUTES,0,0,0), ACCESS_RD, (0, 50), ASN_OBJECT_ID, "ipRouteInfo", "mandatory" ],
		
		'1.3.6.1.2.1.4.22.1.1.0' : [ (NUM_IPNETTOMEDIAS,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_UNSIGNED, "ipNetToMediaIfIndex", "mandatory" ],
		'1.3.6.1.2.1.4.22.1.2.0' : [ (NUM_IPNETTOMEDIAS,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_OCTET_STR, "ipNetToMediaPhysAddress", "mandatory" ],
		'1.3.6.1.2.1.4.22.1.3.0' : [ (NUM_IPNETTOMEDIAS,0,0,0), ACCESS_RW, (4, 4), ASN_IPADDRESS, "ipNetToMediaNetAddress", "mandatory" ],
		'1.3.6.1.2.1.4.22.1.4.0' : [ (NUM_IPNETTOMEDIAS,0,0,0), ACCESS_RW, (1, 4), ASN_INTEGER, "ipNetToMediaType", "mandatory" ],
		
		'1.3.6.1.2.1.4.23.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "ipRoutingDiscards", "mandatory" ],
		
    # TCP  - RFC 1213		
		'1.3.6.1.2.1.6.1.0' : [ (0,0,0,0), ACCESS_RD, (1, 4), ASN_INTEGER, "tcpRtoAlgorithm", "mandatory" ],
		'1.3.6.1.2.1.6.2.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_UNSIGNED, "tcpRtoMin", "mandatory" ],
		'1.3.6.1.2.1.6.3.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_UNSIGNED, "tcpRtoMax", "mandatory" ],
		'1.3.6.1.2.1.6.4.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_INTEGER, "tcpMaxConn", "mandatory" ],
		'1.3.6.1.2.1.6.5.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "tcpActiveOpens", "mandatory" ],
		'1.3.6.1.2.1.6.6.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "tcpPassiveOpens", "mandatory" ],
		'1.3.6.1.2.1.6.7.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "tcpAttemptFails", "mandatory" ],
		'1.3.6.1.2.1.6.8.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "tcpEstabResets", "mandatory" ],
		'1.3.6.1.2.1.6.9.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_GAUGE, "tcpCurrEstab", "mandatory" ],
		'1.3.6.1.2.1.6.10.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "tcpInSegs", "mandatory" ],
		'1.3.6.1.2.1.6.11.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "tcpOutSegs", "mandatory" ],
		'1.3.6.1.2.1.6.12.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "tcpRetransSegs", "mandatory" ],
		
		'1.3.6.1.2.1.6.13.1.1.0' : [ (NUM_TCPCONNS,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "tcpConnState", "mandatory" ],
		'1.3.6.1.2.1.6.13.1.2.0' : [ (NUM_TCPCONNS,0,0,0), ACCESS_RD, (4, 4), ASN_IPADDRESS, "tcpConnLocalAddress", "mandatory" ],
		'1.3.6.1.2.1.6.13.1.3.0' : [ (NUM_TCPCONNS,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "tcpConnLocalPort", "mandatory" ],
		'1.3.6.1.2.1.6.13.1.4.0' : [ (NUM_TCPCONNS,0,0,0), ACCESS_RD, (4, 4), ASN_IPADDRESS, "tcpConnRemAddress", "mandatory" ],
		'1.3.6.1.2.1.6.13.1.5.0' : [ (NUM_TCPCONNS,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "tcpConnRemPort", "mandatory" ],
		
		'1.3.6.1.2.1.6.14.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "tcpInErrs", "mandatory" ],
		'1.3.6.1.2.1.6.15.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "tcpOutRsts", "mandatory" ],
		
    # UDP  - RFC 1213		
		'1.3.6.1.2.1.7.1.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "udpInDatagrams", "mandatory" ],
		'1.3.6.1.2.1.7.2.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "udpNoPorts", "mandatory" ],
		'1.3.6.1.2.1.7.3.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "udpInErrors", "mandatory" ],
		'1.3.6.1.2.1.7.4.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "udpOutDatagrams", "mandatory" ],
		
		'1.3.6.1.2.1.7.5.1.1.0' : [ (NUM_UDPS,0,0,0), ACCESS_RD, (4, 4), ASN_IPADDRESS, "udpLocalAddress", "mandatory" ],
		'1.3.6.1.2.1.7.5.1.2.0' : [ (NUM_UDPS,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "udpLocalPort", "mandatory" ],
		
    # SNMP - RFC 1213		
		'1.3.6.1.2.1.11.1.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInPkts", "mandatory" ],
		'1.3.6.1.2.1.11.2.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpOutPkts", "mandatory" ],
		'1.3.6.1.2.1.11.3.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInBadVersions", "mandatory" ],
		'1.3.6.1.2.1.11.4.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInBadCommunityNames", "mandatory" ],
		'1.3.6.1.2.1.11.5.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInBadCommunityUses", "mandatory" ],
		'1.3.6.1.2.1.11.6.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInASNParseErrs", "mandatory" ],
		'1.3.6.1.2.1.11.8.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInTooBigs", "mandatory" ],
		'1.3.6.1.2.1.11.9.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInNoSuchNames", "mandatory" ],
		'1.3.6.1.2.1.11.10.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInBadValues", "mandatory" ],
		'1.3.6.1.2.1.11.11.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInReadOnlys", "mandatory" ],
		'1.3.6.1.2.1.11.12.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInGenErrs", "mandatory" ],
		'1.3.6.1.2.1.11.13.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInTotalReqVars", "mandatory" ],
		'1.3.6.1.2.1.11.14.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInTotalSetVars", "mandatory" ],
		'1.3.6.1.2.1.11.15.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInGetRequests", "mandatory" ],
		'1.3.6.1.2.1.11.16.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInGetNexts", "mandatory" ],
		'1.3.6.1.2.1.11.17.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInSetRequests", "mandatory" ],
		'1.3.6.1.2.1.11.18.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInGetResponses", "mandatory" ],
		'1.3.6.1.2.1.11.19.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpInTraps", "mandatory" ],
		'1.3.6.1.2.1.11.20.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpOutTooBigs", "mandatory" ],
		'1.3.6.1.2.1.11.21.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpOutNoSuchNames", "mandatory" ],
		'1.3.6.1.2.1.11.22.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpOutBadValues", "mandatory" ],
		'1.3.6.1.2.1.11.24.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpOutGenErrs", "mandatory" ],
		'1.3.6.1.2.1.11.25.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpOutGetRequests", "mandatory" ],
		'1.3.6.1.2.1.11.26.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpOutGetNexts", "mandatory" ],
		'1.3.6.1.2.1.11.27.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpOutSetRequests", "mandatory" ],
		'1.3.6.1.2.1.11.28.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpOutGetResponses", "mandatory" ],
		'1.3.6.1.2.1.11.29.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "snmpOutTraps", "mandatory" ],
		'1.3.6.1.2.1.11.30.0' : [ (0,0,0,0), ACCESS_RW, (1, 2), ASN_INTEGER, "snmpEnableAuthenTraps", "mandatory" ],
		
    # mcAtcNemaIoMapping - McCain		
		'1.3.6.1.4.1.1206.3.21.2.2.3.1.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_NEMA_INBITS), ASN_INTEGER, "mcAtcMaxNemaIoInputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.3.2.1.1.0' : [ (NUM_NEMA_INBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcNemaIoInputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.3.2.1.2.0' : [ (NUM_NEMA_INBITS,0,0,0), ACCESS_P2, (1, IOI_NUMIDS - 1), ASN_INTEGER, "mcAtcNemaIoInputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.3.2.1.3.0' : [ (NUM_NEMA_INBITS,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcNemaIoInputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.3.2.1.4.0' : [ (NUM_NEMA_INBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcAtcNemaIoInputRowLabel", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.3.3.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_NEMA_OUTBITS), ASN_INTEGER, "mcAtcMaxNemaIoOutputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.3.4.1.1.0' : [ (NUM_NEMA_OUTBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcNemaIoOutputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.3.4.1.2.0' : [ (NUM_NEMA_OUTBITS,0,0,0), ACCESS_P2, (1, IOO_NUMIDS - 1), ASN_INTEGER, "mcAtcNemaIoOutputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.3.4.1.3.0' : [ (NUM_NEMA_OUTBITS,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcNemaIoOutputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.3.4.1.4.0' : [ (NUM_NEMA_OUTBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcAtcNemaIoOutputRowLabel", "mandatory" ],
		
    # mcAtcTs2IoMapping		
		'1.3.6.1.4.1.1206.3.21.2.2.4.1.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_TS2_BIUS), ASN_INTEGER, "mcAtcMaxTs2Bius", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.4.2.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_TS2_BIU_INPUTS), ASN_INTEGER, "mcAtcMaxTs2BiuInputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.4.3.1.1.0' : [ (NUM_TS2_BIUS,NUM_TS2_BIU_INPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcTs2IoBiuInNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.4.3.1.2.0' : [ (NUM_TS2_BIUS,NUM_TS2_BIU_INPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcTs2IoInputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.4.3.1.3.0' : [ (NUM_TS2_BIUS,NUM_TS2_BIU_INPUTS,0,0), ACCESS_P2, (1, IOI_NUMIDS - 1), ASN_INTEGER, "mcAtcTs2IoInputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.4.3.1.4.0' : [ (NUM_TS2_BIUS,NUM_TS2_BIU_INPUTS,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcTs2IoInputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.4.3.1.5.0' : [ (NUM_TS2_BIUS,NUM_TS2_BIU_INPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcAtcTs2IoInputRowLabel", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.4.4.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_TS2_BIU_OUTPUTS), ASN_INTEGER, "mcAtcMaxTs2IoBiuOutputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.4.5.1.1.0' : [ (NUM_TS2_BIUS,NUM_TS2_BIU_OUTPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcTs2IoBiuOutNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.4.5.1.2.0' : [ (NUM_TS2_BIUS,NUM_TS2_BIU_OUTPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcTs2IoOutputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.4.5.1.3.0' : [ (NUM_TS2_BIUS,NUM_TS2_BIU_OUTPUTS,0,0), ACCESS_P2, (1, IOO_NUMIDS - 1), ASN_INTEGER, "mcAtcTs2IoOutputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.4.5.1.4.0' : [ (NUM_TS2_BIUS,NUM_TS2_BIU_OUTPUTS,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcTs2IoOutputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.4.5.1.5.0' : [ (NUM_TS2_BIUS,NUM_TS2_BIU_OUTPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcAtcTs2IoOutputRowLabel", "mandatory" ],
		
    # mcAtcFioIoMapping		
		'1.3.6.1.4.1.1206.3.21.2.2.5.1.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_2070_2A_INBITS), ASN_INTEGER, "mcAtcMaxFioIoInputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.5.2.1.1.0' : [ (NUM_2070_2A_INBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcFioIoInputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.5.2.1.2.0' : [ (NUM_2070_2A_INBITS,0,0,0), ACCESS_P2, (1, IOI_NUMIDS - 1), ASN_INTEGER, "mcAtcFioIoInputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.5.2.1.3.0' : [ (NUM_2070_2A_INBITS,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcFioIoInputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.5.2.1.4.0' : [ (NUM_2070_2A_INBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcAtcFioIoInputRowLabel", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.5.3.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_2070_2A_OUTBITS), ASN_INTEGER, "mcAtcMaxFioIoOutputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.5.4.1.1.0' : [ (NUM_2070_2A_OUTBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcFioIoOutputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.5.4.1.2.0' : [ (NUM_2070_2A_OUTBITS,0,0,0), ACCESS_P2, (1, IOO_NUMIDS - 1), ASN_INTEGER, "mcAtcFioIoOutputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.5.4.1.3.0' : [ (NUM_2070_2A_OUTBITS,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcFioIoOutputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.5.4.1.4.0' : [ (NUM_2070_2A_OUTBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcAtcFioIoOutputRowLabel", "mandatory" ],
		
    # mcAtcItsIoMapping		
		'1.3.6.1.4.1.1206.3.21.2.2.6.1.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_ITS_SIUS), ASN_INTEGER, "mcAtcMaxItsSius", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.6.2.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_ITS_SIU_INPUTS), ASN_INTEGER, "mcAtcMaxItsSiuInputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.6.3.1.1.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_INPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcItsIoSiuInNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.6.3.1.2.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_INPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcItsIoInputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.6.3.1.3.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_INPUTS,0,0), ACCESS_P2, (1, IOI_NUMIDS - 1), ASN_INTEGER, "mcAtcItsIoInputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.6.3.1.4.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_INPUTS,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcItsIoInputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.6.3.1.5.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_INPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcAtcItsIoInputRowLabel", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.6.4.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_ITS_SIU_OUTPUTS), ASN_INTEGER, "mcAtcMaxItsIoSiuOutputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.6.5.1.1.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_OUTPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcItsIoSiuOutNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.6.5.1.2.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_OUTPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcItsIoOutputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.6.5.1.3.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_OUTPUTS,0,0), ACCESS_P2, (1, IOO_NUMIDS - 1), ASN_INTEGER, "mcAtcItsIoOutputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.6.5.1.4.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_OUTPUTS,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcItsIoOutputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.6.5.1.5.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_OUTPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcAtcItsIoOutputRowLabel", "mandatory" ],
		
    # mcAtcItsDevices		
		'1.3.6.1.4.1.1206.3.21.2.2.7.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_ITS_DEVICES), ASN_INTEGER, "mcAtcMaxItsDevices", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.7.2.1.1.0' : [ (MAX_ITS_DEVICES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcItsDeviceNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.7.2.1.2.0' : [ (MAX_ITS_DEVICES,0,0,0), ACCESS_P, (0, 2), ASN_INTEGER, "mcAtcItsDevicePresent", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.7.2.1.4.0' : [ (MAX_ITS_DEVICES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcItsDeviceStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.7.2.1.5.0' : [ (MAX_ITS_DEVICES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcItsDeviceFaultFrame", "mandatory" ],
		
    # mcAtcIoLogic		
		'1.3.6.1.4.1.1206.3.21.2.2.8.1.0' : [ (0,0,0,0), ACCESS_RD, (0, NUM_IOLOGIC_GATES), ASN_INTEGER, "mcAtcMaxIoLogicGates", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.1.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicGateNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.2.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, 4), ASN_INTEGER, "mcAtcIoLogicType", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.3.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, 10), ASN_INTEGER, "mcAtcIoLogicOutputMode", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.4.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, 1), ASN_INTEGER, "mcAtcIoLogicOutputInvert", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.5.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicOutputDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.6.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicOutputExtension", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.7.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, IOGO_NUMIDS - 1), ASN_INTEGER, "mcAtcIoLogicOutputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.8.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicOutputFunctionIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.9.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, 1), ASN_INTEGER, "mcAtcIoLogicInput1Invert", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.10.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicInput1Delay", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.11.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicInput1Extension", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.12.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, IOGI_NUMIDS - 1), ASN_INTEGER, "mcAtcIoLogicInput1Function", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.13.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicInput1FunctionIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.14.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, 1), ASN_INTEGER, "mcAtcIoLogicInput2Invert", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.15.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicInput2Delay", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.16.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicInput2Extension", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.17.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, IOGI_NUMIDS - 1), ASN_INTEGER, "mcAtcIoLogicInput2Function", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.18.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicInput2FunctionIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.19.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, 1), ASN_INTEGER, "mcAtcIoLogicInput3Invert", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.20.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicInput3Delay", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.21.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicInput3Extension", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.22.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, IOGI_NUMIDS - 1), ASN_INTEGER, "mcAtcIoLogicInput3Function", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.23.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicInput3FunctionIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.24.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, 1), ASN_INTEGER, "mcAtcIoLogicInput4Invert", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.25.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicInput4Delay", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.26.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicInput4Extension", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.27.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, IOGI_NUMIDS - 1), ASN_INTEGER, "mcAtcIoLogicInput4Function", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.28.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcIoLogicInput4FunctionIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.8.3.1.29.0' : [ (NUM_IOLOGIC_GATES,0,0,0), ACCESS_P2, (1, 4), ASN_INTEGER, "mcAtcIoLogicDelayExtendUnits", "mandatory" ],
		
    # mcAtcAuxSwitch		
		'1.3.6.1.4.1.1206.3.21.2.2.9.1.0' : [ (0,0,0,0), ACCESS_P2, (1, IOI_NUMIDS - 1), ASN_INTEGER, "mcAtcAuxSwitchInputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.2.9.2.0' : [ (0,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcAuxSwitchInputIndex", "mandatory" ],
		
    # mcAtcCoord - McCain		
		'1.3.6.1.4.1.1206.3.21.2.3.1.0' : [ (0,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "mcAtcCoordMaxTransitionCycles", "deprecated" ],
		'1.3.6.1.4.1.1206.3.21.2.3.2.0' : [ (0,0,0,0), ACCESS_P, (2, 4), ASN_INTEGER, "mcAtcCoordPermStrategy", "deprecated" ],
		'1.3.6.1.4.1.1206.3.21.2.3.3.0' : [ (0,0,0,0), ACCESS_P, (2, 4), ASN_INTEGER, "mcAtcCoordOmitStrategy", "deprecated" ],
		
		'1.3.6.1.4.1.1206.3.21.2.3.4.1.1.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCoordSplitManualPermit", "deprecated" ],
		'1.3.6.1.4.1.1206.3.21.2.3.4.1.2.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCoordSplitManualOmit", "deprecated" ],
		'1.3.6.1.4.1.1206.3.21.2.3.4.1.3.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCoordSplitMinTime", "deprecated" ],
		'1.3.6.1.4.1.1206.3.21.2.3.4.1.4.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_P2, (SPLIT_MODE_OTHER, SPLIT_MODE_NONACT), ASN_INTEGER, "mcAtcSplitMode", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.4.1.5.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_P, (0, MAX_RESERVICE_COUNT_LIMIT), ASN_INTEGER, "mcAtcCoordSplitMaxReserviceCount", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.4.1.6.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCoordSplitBeginReservice", "deprecated" ],
		'1.3.6.1.4.1.1206.3.21.2.3.4.1.7.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCoordSplitEndReservice", "deprecated" ],
		'1.3.6.1.4.1.1206.3.21.2.3.4.1.8.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_P2, (0, 1), ASN_INTEGER, "mcAtcCoordSplitPreferred", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.4.1.9.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCoordSplitGapOutTime", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.3.5.0' : [ (0,0,0,0), ACCESS_P, (1, 2), ASN_INTEGER, "mcAtcCoordSyncPoint", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.6.0' : [ (0,0,0,0), ACCESS_P, (2, 3), ASN_INTEGER, "mcAtcCoordNoEarlyReturn", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.7.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcLocalCycleTimer", "optional" ],
		
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.1.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, 5), ASN_INTEGER, "mcAtcPatternCoordCorrectionMode", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.2.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, 6), ASN_INTEGER, "mcAtcPatternCoordMaximumMode", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.3.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "mcAtcPatternCoordForceMode", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.4.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "mcAtcPatternCoordPermStrategy", "deprecated" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.5.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "mcAtcPatternCoordOmitStrategy", "deprecated" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.6.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "mcAtcPatternCoordNoEarlyReturn", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.7.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P2, (1, 4), ASN_INTEGER, "mcAtcPatternPhaseTimingSet", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.8.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P2, (1, 4), ASN_INTEGER, "mcAtcPatternPhaseOptionSet", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.9.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P2, (1, 4), ASN_INTEGER, "mcAtcPatternVehOverlapSet", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.10.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "mcAtcPatternVehDetSet", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.11.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "mcAtcPatternVehDetDiagSet", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.12.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "mcAtcPatternPedDetSet", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.13.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "mcAtcPatternPedDetDiagSet", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.14.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcPatternDetectorReset", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.15.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPatternMax2Phases", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.16.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P2, (1, 4), ASN_INTEGER, "mcAtcPatternTexasDiamondType", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.17.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "mcAtcPatternPrioritySet", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.18.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "mcAtcPatternPedOverlapSet", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.19.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P2, (0, 1), ASN_INTEGER, "mcAtcPatternCoordPercentValues", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.20.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcPatternActuatedCoordEnable", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.21.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPatternActuatedCoordValue", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.22.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPatternMax3Phases", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.23.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPatternMax4Phases", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.24.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (COORD_INC_PEDS_UNIT, COORD_INC_PEDS_ALLPEDS), ASN_INTEGER, "mcAtcPatternCoverPeds", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.25.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (COORD_YIELD_UNIT, COORD_YIELD_ALLPERM), ASN_INTEGER, "mcAtcPatternYieldStrategy", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.8.1.26.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (0, MAX_SPLITS), ASN_INTEGER, "mcAtcPatternSplitAdjustmentNumber", "mandatory" ],

		'1.3.6.1.4.1.1206.3.21.2.3.9.0' : [ (0,0,0,0), ACCESS_P, (1, 6), ASN_INTEGER, "mcAtcGlobalCoordMaximumMode", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.10.0' : [ (0,0,0,0), ACCESS_P, (0, MAX_RLP_ACTIVATIONS_PER_CYCLE), ASN_INTEGER, "mcAtcRedLightProtectionActivationsPerCycle", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.11.0' : [ (0,0,0,0), ACCESS_P, (0, MAX_RLP_CYCLE_HEADWAY), ASN_INTEGER, "mcAtcRedLightProtectionCycleHeadway", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.12.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcCoordActCoordFloatingForceoffOverride", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.13.0' : [ (0,0,0,0), ACCESS_RD, (0, 510), ASN_INTEGER, "mcAtcLocalCycleLength", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.3.14.1.0' : [ (MAX_PATTERNS,MAX_RINGS,0,0), ACCESS_P, (0, 999), ASN_INTEGER, "mcAtcRingOffsetV1", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.15.1.1.0' : [ (MAX_PATTERNS,MAX_RINGS,0,0), ACCESS_P, (0, 999), ASN_INTEGER, "mcAtcRingOffset", "optional" ],
		
		'1.3.6.1.4.1.1206.3.21.2.3.16.0' : [ (0,0,0,0), ACCESS_P, (COORD_INC_PEDS_PEDCALLS, COORD_INC_PEDS_ALLPEDS), ASN_INTEGER, "mcAtcCoordCoverPeds", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.17.0' : [ (0,0,0,0), ACCESS_P, (COORD_YIELD_STANDARD, COORD_YIELD_ALLPERM), ASN_INTEGER, "mcAtcCoordYieldStrategy", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.18.1.1.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (ADJUSTMENT_ABSOLUTE, ADJUSTMENT_MAX), ASN_INTEGER, "mcAtcAdjustmentType", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.19.1.1.0' : [ (MAX_PATTERNS,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcAdjustmentMinimum", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.19.1.2.0' : [ (MAX_PATTERNS,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcAdjustmentMaximum", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.20.0' : [ (0,0,0,0), ACCESS_P, (1, 100), ASN_INTEGER, "mcAtcCoordReducePhasePercent", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.3.21.0' : [ (0,0,0,0), ACCESS_P, (1, INT8U_MAX), ASN_INTEGER, "mcAtcCoordExtendPhasePercent", "mandatory" ],

    # mcAtcPedOverlap - McCain		
		'1.3.6.1.4.1.1206.3.21.2.4.1.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_OVERLAP_TABLES), ASN_INTEGER, "mcAtcMaxPedOverlapSets", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.4.2.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_PED_OVERLAPS), ASN_INTEGER, "mcAtcMaxPedOverlaps", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.4.3.1.1.0' : [ (MAX_OVERLAP_TABLES,MAX_PED_OVERLAPS,0,0), ACCESS_RD, (1, MAX_OVERLAP_TABLES), ASN_INTEGER, "mcAtcPedOverlapSet", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.4.3.1.2.0' : [ (MAX_OVERLAP_TABLES,MAX_PED_OVERLAPS,0,0), ACCESS_RD, (1, MAX_PED_OVERLAPS), ASN_INTEGER, "mcAtcPedOverlapNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.4.3.1.3.0' : [ (MAX_OVERLAP_TABLES,MAX_PED_OVERLAPS,0,0), ACCESS_P, (0, MAX_PHASES), ASN_OCTET_STR, "mcAtcPedOverlapIncludedPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.4.3.1.4.0' : [ (MAX_OVERLAP_TABLES,MAX_PED_OVERLAPS,0,0), ACCESS_P, (0, MAX_PHASES), ASN_OCTET_STR, "mcAtcPedOverlapExcludedPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.4.3.1.5.0' : [ (MAX_OVERLAP_TABLES,MAX_PED_OVERLAPS,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "mcAtcPedOverlapIntervals", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.4.3.1.6.0' : [ (MAX_OVERLAP_TABLES,MAX_PED_OVERLAPS,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPedOverlapCallPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.4.3.1.7.0' : [ (MAX_OVERLAP_TABLES,MAX_PED_OVERLAPS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPedOverlapOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.4.3.1.8.0' : [ (MAX_OVERLAP_TABLES,MAX_PED_OVERLAPS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPedOverlapWalkTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.4.3.1.9.0' : [ (MAX_OVERLAP_TABLES,MAX_PED_OVERLAPS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPedOverlapClearanceTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.4.3.1.10.0' : [ (MAX_OVERLAP_TABLES,MAX_PED_OVERLAPS,0,0), ACCESS_P, (1, 2), ASN_INTEGER, "mcAtcPedOverlapRecall", "mandatory" ],
		
    # mcAtcPriority - McCain		
		'1.3.6.1.4.1.1206.3.21.2.5.1.0' : [ (0,0,0,0), ACCESS_P2, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPriorityGlobalEnable", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.2.0' : [ (0,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_GAUGE, "mcAtcPriorityGlobalNodeNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.3.0' : [ (0,0,0,0), ACCESS_P, (0, 30), ASN_OCTET_STR, "mcAtcPriorityGlobalNodeName", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.4.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityGlobalHeadway", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.5.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityGlobalPreemptLockout", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.6.0' : [ (0,0,0,0), ACCESS_RW, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPriorityGlobalOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.11.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_TSP_TABLES), ASN_INTEGER, "mcAtcMaxPriorityStrategySets", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.12.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_TSP_STRATEGIES), ASN_INTEGER, "mcAtcMaxPriorityStrategies", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.1.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategySet", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.2.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.4.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P2, (0, INT16U_MAX), ASN_INTEGER, "mcATCPriorityStrategyOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.5.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P2, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyServicePhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.6.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyPhaseCalls", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.7.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyPhaseOmits", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.8.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyPedOmits", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.9.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyQueueJumpPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.10.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyETA", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.11.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "mcAtcPriorityStrategyInputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.12.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, 16), ASN_INTEGER, "mcAtcPriorityStrategyInputFunctionIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.13.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (1, 2), ASN_INTEGER, "mcAtcPriorityStrategyInputType", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.14.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "mcAtcPriorityStrategyRequestMode", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.15.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (1, 5), ASN_INTEGER, "mcAtcPriorityStrategyCheckoutMode", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.16.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyCheckoutTimeout", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.17.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyMaxPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.18.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyMaxPresenceClearTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.19.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyMinimumOnTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.20.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyMinimumOffTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.21.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyDelayTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.22.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyExtendTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.23.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyHeadwayTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.24.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyPreemptLockoutTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.25.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, MAX_PHASES), ASN_OCTET_STR, "mcAtcPriorityStrategyMaximumReductionTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.26.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, MAX_PHASES), ASN_OCTET_STR, "mcAtcPriorityStrategyMaximumExtensionTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.27.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, MAX_PHASES), ASN_OCTET_STR, "mcAtcPriorityStrategyQueueJumpTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.28.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityStrategyArrivalWindow", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.29.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_RD, (1, TSP_STRAT_STATE_MAX_STATE), ASN_INTEGER, "mcAtcPriorityStrategyState", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.13.1.30.0' : [ (MAX_TSP_TABLES,MAX_TSP_STRATEGIES,0,0), ACCESS_RD, (1, TSP_STATE_IN_MAX_STATE), ASN_INTEGER, "mcAtcPriorityStrategyInputState", "optional" ],
		
		'1.3.6.1.4.1.1206.3.21.2.5.14.1.1.0' : [ (MAX_TSP_STRATEGIES,0,0,0), ACCESS_RW, (0, 1), ASN_INTEGER, "mcAtcPriorityControlRequest", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.3.21.2.5.14.1.2.0' : [ (MAX_TSP_STRATEGIES,0,0,0), ACCESS_RW, (0, 1), ASN_INTEGER, "mcAtcPriorityControlCheckout", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.3.21.2.5.14.1.3.0' : [ (MAX_TSP_STRATEGIES,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityControlETA", "mandatory" ], # | AF_BU
		
		'1.3.6.1.4.1.1206.3.21.2.5.15.0' : [ (0,0,0,0), ACCESS_RD, (1, PRIORITY_IMAGE_MAX_ENTRIES), ASN_INTEGER, "mcAtcMaxPriorityExtendedProcesses", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.5.16.1.1.0' : [ (PRIORITY_IMAGE_MAX_ENTRIES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityExtendedNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.16.1.2.0' : [ (PRIORITY_IMAGE_MAX_ENTRIES,0,0,0), ACCESS_P, (0, 4), ASN_INTEGER, "mcAtcPriorityExtendedType", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.16.1.3.0' : [ (PRIORITY_IMAGE_MAX_ENTRIES,0,0,0), ACCESS_P, (0, PRIORITY_IMAGE_NAME_MAX), ASN_OCTET_STR, "mcAtcPriorityExtendedName", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.5.17.0' : [ (0,0,0,0), ACCESS_RD, (1, PRIORITY_IMAGE_MAX_IMAGES), ASN_INTEGER, "mcAtcMaxPriorityExtendedProcessTable", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.5.18.1.1.0' : [ (PRIORITY_IMAGE_MAX_ENTRIES,PRIORITY_IMAGE_MAX_IMAGES,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityExtendedProcessNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.18.1.2.0' : [ (PRIORITY_IMAGE_MAX_ENTRIES,PRIORITY_IMAGE_MAX_IMAGES,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcPriorityExtendedProcessImageNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.5.18.1.3.0' : [ (PRIORITY_IMAGE_MAX_ENTRIES,PRIORITY_IMAGE_MAX_IMAGES,0,0), ACCESS_P, (0, PRIORITY_IMAGE_MAX_SIZE), ASN_OCTET_STR, "mcAtcPriorityExtendedProcessImageSegment", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.5.19.0' : [ (0,0,0,0), ACCESS_RD, (1, TSP_STATE_MAX_STATE), ASN_INTEGER, "mcAtcPriorityState", "mandatory" ],
		
    # mcAtcDetectorVOSLog - McCain		
		'1.3.6.1.4.1.1206.3.21.2.6.2.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_LOG_DETS), ASN_INTEGER, "mcAtcDetVOSLogMaxDetectors", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.6.3.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_VOS_LOGS), ASN_INTEGER, "mcAtcDetVOSLogMaxEntries", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.6.4.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_VOS_LOGS), ASN_INTEGER, "mcAtcDetVOSLogNumEntries", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.6.5.1.1.0' : [ (MAX_VOS_LOGS,0,0,0), ACCESS_RD, (1, MAX_VOS_LOGS), ASN_INTEGER, "mcAtcDetVOSLogNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.6.5.1.2.0' : [ (MAX_VOS_LOGS,0,0,0), ACCESS_RW, (0, SIZE_VOS_ROW), ASN_OCTET_STR, "mcAtcDetVOSLogEntryData", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.6.6.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "mcAtcDetVOSLogStartSeqNum", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.6.7.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "mcAtcDetVOSLogStartTimestamp", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.6.8.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "mcAtcDetVOSLogClearSeqNum", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.6.9.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "mcAtcDetVOSLogClearTimestamp", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.6.10.0' : [ (0,0,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "mcAtcDetVOSLogMode", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.6.11.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcDetVOSLogCombinedPeriods", "mandatory" ],
		
    # mcAtcSpeedTrap - McCain		
		'1.3.6.1.4.1.1206.3.21.2.7.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_SPEED_TRAPS), ASN_INTEGER, "mcAtcMaxSpeedTraps", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.7.3.1.1.0' : [ (MAX_SPEED_TRAPS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcSpeedTrapIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.7.3.1.2.0' : [ (MAX_SPEED_TRAPS,0,0,0), ACCESS_P, (0, MAX_DETECTORS), ASN_INTEGER, "mcAtcSpeedTrapDet1", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.7.3.1.3.0' : [ (MAX_SPEED_TRAPS,0,0,0), ACCESS_P, (0, MAX_DETECTORS), ASN_INTEGER, "mcAtcSpeedTrapDet2", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.7.3.1.4.0' : [ (MAX_SPEED_TRAPS,0,0,0), ACCESS_P, (0, 9990), ASN_INTEGER, "mcAtcSpeedTrapDistance", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.7.3.1.5.0' : [ (MAX_SPEED_TRAPS,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpeedTrapAvgSpeed", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.7.3.1.6.0' : [ (MAX_SPEED_TRAPS,0,0,0), ACCESS_RD, (0, MAX_SPEED_BINS), ASN_OCTET_STR, "mcAtcSpeedTrapBinCounts", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.7.6.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_SPEED_BINS), ASN_INTEGER, "mcAtcMaxSpeedBins", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.7.7.1.1.0' : [ (MAX_SPEED_BINS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcSpeedBinIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.7.7.1.2.0' : [ (MAX_SPEED_BINS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcSpeedBinRange", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.7.8.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_SPD_LOGS), ASN_INTEGER, "mcAtcSpeedTrapLogMaxEntries", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.7.9.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_SPD_LOGS), ASN_INTEGER, "mcAtcSpeedTrapLogNumEntries", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.7.10.1.1.0' : [ (MAX_SPD_LOGS,0,0,0), ACCESS_RD, (1, MAX_SPD_LOGS), ASN_INTEGER, "mcAtcSpeedTrapLogIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.7.10.1.2.0' : [ (MAX_SPD_LOGS,0,0,0), ACCESS_RD, (0, SIZE_SPEED_ROW), ASN_OCTET_STR, "mcAtcSpeedTrapLogEntryData", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.7.11.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "mcAtcSpeedTrapLogStartSeqNum", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.7.12.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "mcAtcSpeedTrapLogStartTimestamp", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.7.13.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "mcAtcSpeedTrapLogClearSeqNum", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.7.14.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "mcAtcSpeedTrapLogClearTimestamp", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.7.15.0' : [ (0,0,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "mcAtcSpeedTrapLogMode", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.7.16.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpeedTrapLogPeriod", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.7.17.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcLogOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.7.18.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "mcAtcSpeedTrapSeqNum", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.7.19.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "mcAtcSpeedTrapTimestamp", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.7.20.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "mcAtcSpeedTrapDuration", "mandatory" ],
		
    # mcAtcUnit - McCain		
		'1.3.6.1.4.1.1206.3.21.2.8.1.0' : [ (0,0,0,0), ACCESS_P2, (0, INT32U_MAX), ASN_GAUGE, "mcAtcSystemID", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.2.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcUnitStartUpAllRed", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.3.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcUnitMinYellow", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.7.0' : [ (0,0,0,0), ACCESS_P2, (0, 1), ASN_INTEGER, "mcAtcTexasDiamondMode", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.8.0' : [ (0,0,0,0), ACCESS_P2, (2, 4), ASN_INTEGER, "mcAtcTexasDiamondType", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.9.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcNoStartVehCall", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.10.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcNoStartPedCall", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.11.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcStartupNextPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.12.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcOmniAlarmStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.13.0' : [ (0,0,0,0), ACCESS_P2, (0, 1), ASN_INTEGER, "mcAtcDualPedestrianControl", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.14.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_UNSIGNED, "mcAtcDocVersion", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.15.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcUnitIntervalAdvanceOverride", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.16.0' : [ (0,0,0,0), ACCESS_P, (EXIT_AUTO_FLASH_ALL_RED_DISABLED, EXIT_AUTO_FLASH_ALL_RED_ENABLED), ASN_INTEGER, "mcAtcUnitExitAutoFlashAllRedEnable", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.17.0' : [ (0,0,0,0), ACCESS_P, (EXIT_AUTO_FLASH_ALL_RED_MIN, EXIT_AUTO_FLASH_ALL_RED_MAX), ASN_INTEGER, "mcAtcUnitExitAutoFlashAllRedTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.8.18.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcRequestedPatternStatus", "mandatory" ],

    # mcAtcCycleMOELog - McCain		
		'1.3.6.1.4.1.1206.3.21.2.9.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_MOE_LOGS), ASN_INTEGER, "mcAtcCycleMOELogMaxEntries", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.9.2.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_MOE_LOGS), ASN_INTEGER, "mcAtcCycleMOELogNumEntries", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.9.3.1.1.0' : [ (MAX_MOE_LOGS,0,0,0), ACCESS_RD, (1, MAX_MOE_LOGS), ASN_INTEGER, "mcAtcCycleMOELogEntryNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.9.3.1.2.0' : [ (MAX_MOE_LOGS,0,0,0), ACCESS_RD, (0, SIZE_MOE_ROW), ASN_OCTET_STR, "mcAtcCycleMOELogEntryData", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.9.4.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "mcAtcCycleMOELogStartSeqNum", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.9.5.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "mcAtcCycleMOELogStartTimestamp", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.9.6.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "mcAtcCycleMOELogClearSeqNum", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.9.7.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "mcAtcCycleMOELogClearTimestamp", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.9.8.0' : [ (0,0,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "mcAtcCycleMOELogMode", "optional" ],
		
    # mcAtcControllerLog - McCain		
		'1.3.6.1.4.1.1206.3.21.2.10.1.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_CNTRL_LOG_EVENTS), ASN_INTEGER, "mcAtcControllerLogMaxEntries", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.10.2.0' : [ (0,0,0,0), ACCESS_RD, (0, NUM_CNTRL_LOG_EVENTS), ASN_INTEGER, "mcAtcControllerLogNumEntries", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.10.3.1.1.0' : [ (NUM_CNTRL_LOG_EVENTS,0,0,0), ACCESS_RD, (1, NUM_CNTRL_LOG_EVENTS), ASN_INTEGER, "mcAtcControllerLogEntryNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.10.3.1.2.0' : [ (NUM_CNTRL_LOG_EVENTS,0,0,0), ACCESS_RD, (0, SIZE_CNTRL_LOG_ROW), ASN_OCTET_STR, "mcAtcControllerLogEntryData", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.10.4.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_GAUGE, "mcAtcControllerLogStartSeqNum", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.5.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_GAUGE, "mcAtcControllerLogStartTimestamp", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.6.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_GAUGE, "mcAtcControllerLogClearSeqNum", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.7.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_GAUGE, "mcAtcControllerLogClearTimestamp", "optional" ],
		
		'1.3.6.1.4.1.1206.3.21.2.10.9.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaPowerOnOff", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.10.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaLowBattery", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.11.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaCycleFault", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.12.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaCoordFault", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.13.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaCoordFail", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.14.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaCycleFail", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.15.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaMMUflash", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.16.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaLocalFlash", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.17.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaLocalFree", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.18.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaPreemptStatusChange", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.19.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaResponseFault", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.20.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaAlarmStatusChange", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.21.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaDoorStatusChange", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.22.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaPatternChange", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.23.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaDetectorStatusChange", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.24.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaCommStatusChange", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.25.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaCommandChange", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.26.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaDataChangeKeyboard", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.27.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaControllerDownload", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.28.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaAccessCode", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.29.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaPriority", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.30.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaManCtrlEnable", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.10.31.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcControllerLogEnaStopTime", "optional" ],
		
    # mcAtcPhase - McCain		
		'1.3.6.1.4.1.1206.3.21.2.11.1.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_PHASE_TABLES), ASN_INTEGER, "mcAtcMaxPhaseSets", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.1.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseSet", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.2.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseWalk", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.3.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhasePedestrianClear", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.4.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseMinimumGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.5.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhasePassage", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.6.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseMaximum1", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.7.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseMaximum2", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.8.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseYellowChange", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.9.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseRedClear", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.10.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseRedRevert", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.11.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseAddedInitial", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.12.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseMaximumInitial", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.13.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseTimeBeforeReduction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.14.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseCarsBeforeReduction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.15.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseTimeToReduce", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.16.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseReduceBy", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.17.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseMinimumGap", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.18.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseDynamicMaxLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.19.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseDynamicMaxStep", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.21.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P2, (0, INT16U_MAX), ASN_INTEGER, "mcAtc1202PhaseOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.24.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P2, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPhaseOptions2", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.25.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseAlternateWalk", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.26.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseAdvanceWalk", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.27.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseDelayWalk", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.28.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseAlternatePassage", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.29.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseStartDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.30.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseCondSvcMin", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.31.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseGreenClear", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.32.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseAlternatePedClear", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.33.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseAlternateMinGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.34.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseMaximum3", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.35.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseMaximum4", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.36.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcRedLightProtectionTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.2.1.37.0' : [ (MAX_PHASE_TABLES,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcRedLightProtectionMaxApplications", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.3.1.1.0' : [ (MAX_PHASES,0,0,0), ACCESS_P2, (0, INT16U_MAX), ASN_INTEGER, "mcAtc1202PhaseConfigOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.3.1.2.0' : [ (MAX_PHASES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseStartup", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.3.1.3.0' : [ (MAX_PHASES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PhaseRing", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.3.1.4.0' : [ (MAX_PHASES,0,0,0), ACCESS_P2, (0, 16), ASN_OCTET_STR, "mcAtc1202PhaseConcurrency", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.4.1.1.0' : [ (MAX_PHASES,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseControlRedExtension", "mandatory" ], #| AF_BU
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.1.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, 2550), ASN_INTEGER, "mcAtcPhaseWalkTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.2.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, 2550), ASN_INTEGER, "mcAtcPhasePedClearTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.3.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, 2550), ASN_INTEGER, "mcAtcPhaseMinimumGreenTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.4.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhasePassageTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.5.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, 2550), ASN_INTEGER, "mcAtcPhaseMaxTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.6.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseYellowTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.7.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseRedClearTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.8.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseRedRevertTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.9.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, 2550), ASN_INTEGER, "mcAtcPhaseInitialTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.10.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, 2550), ASN_INTEGER, "mcAtcPhaseAdvanceWalkTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.11.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, 2550), ASN_INTEGER, "mcAtcPhaseDelayWalkTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.12.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseStartDelayTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.13.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseGreenClearTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.14.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseGapReductionTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.15.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, 2550), ASN_INTEGER, "mcAtcPhaseGreenElapsedTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.16.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseYellowElapsedTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.17.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseRedElapsedTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.18.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, 2550), ASN_INTEGER, "mcAtcPhaseWalkElapsedTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.19.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, 2550), ASN_INTEGER, "mcAtcPhasePedClearElapsedTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.20.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, 2550), ASN_INTEGER, "mcAtcPhaseWaitTimer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.21.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseGreenElapsedTimerSec", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.22.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseWalkElapsedTimerSec", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.23.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhasePedClearElapsedTimerSec", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.11.5.1.24.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPhaseWaitTimerSec", "mandatory" ],
		
    # mcAtcOverlap - McCain		
		'1.3.6.1.4.1.1206.3.21.2.12.1.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_OVERLAP_TABLES), ASN_INTEGER, "mcAtcMaxOverlapSets", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.1.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcOverlapSet", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.2.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P2, (2, 6), ASN_INTEGER, "mcAtcOverlapType", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.3.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P2, (0, MAX_PHASES), ASN_OCTET_STR, "mcAtcOverlapIncludedPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.4.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P2, (0, MAX_PHASES), ASN_OCTET_STR, "mcAtcOverlapModifierPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.5.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcOverlapTrailGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.6.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcOverlapTrailYellow", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.7.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcOverlapTrailRed", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.8.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcOverlapStartDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.9.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P, (0, MAX_PHASES), ASN_OCTET_STR, "mcAtcOverlapExcludedPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.10.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P, (0, MAX_PHASES), ASN_OCTET_STR, "mcAtcOverlapExcludedPeds", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.11.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcOverlapNoTrailGreenPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.12.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcOverlapCallPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.13.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcOverlapOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.14.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P, (0, MAX_PHASES), ASN_OCTET_STR, "mcAtcOverlapExcludedWalks", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.15.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcOverlapNoTrailGreenNextPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.12.2.1.16.0' : [ (MAX_OVERLAP_TABLES,MAX_VEH_OVERLAPS,0,0), ACCESS_P, (0, 16), ASN_OCTET_STR, "mcAtcOverlapExcludedPedOverlaps", "mandatory" ], 
		
    # mcAtcDetector - McCain		
		'1.3.6.1.4.1.1206.3.21.2.13.1.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_DETECTOR_TABLES), ASN_INTEGER, "mcAtcMaxVehicleDetectorSets", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.1.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcVehicleDetectorSet", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.2.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202VehicleDetectorOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.3.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202VehicleDetectorCallPhase", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.4.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202VehicleDetectorSwitchPhase", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.5.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtc1202VehicleDetectorDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.6.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202VehicleDetectorExtend", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.7.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202VehicleDetectorQueueLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.8.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202VehicleDetectorNoActivity", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.9.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202VehicleDetectorMaxPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.10.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202VehicleDetectorErraticCounts", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.11.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202VehicleDetectorFailTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.12.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, 9990), ASN_INTEGER, "mcAtcVehicleDetectorVOSLength", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.13.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcVehicleDetectorOptions2", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.14.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcVehicleDetectorExtraCallPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.15.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcVehicleDetectorCallOverlaps", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.2.1.16.0' : [ (MAX_DETECTOR_TABLES,MAX_DETECTORS,0,0), ACCESS_P2, (0, MAX_PHASES), ASN_INTEGER, "mcAtcRedLightProtectionEnable", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.13.3.1.1.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcVehicleDetectorVolume", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.3.1.2.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcVehicleDetectorOccupancy", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.13.3.1.3.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcVehicleDetectorSpeed", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.13.4.1.1.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RW, (0, 1), ASN_INTEGER, "mcAtcVehicleDetectorControlState", "mandatory" ], # | AF_BU
		
		'1.3.6.1.4.1.1206.3.21.2.13.5.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcVehicleDataCollectionPeriod", "mandatory" ],
		
    # mcAtcPedestrianDetector - McCain		
		'1.3.6.1.4.1.1206.3.21.2.14.1.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_DETECTOR_TABLES), ASN_INTEGER, "mcAtcMaxPedestrianDetectorSets", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.14.2.1.1.0' : [ (MAX_DETECTOR_TABLES,MAX_PED_DETECTORS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcPedestrianDetectorSet", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.14.2.1.2.0' : [ (MAX_DETECTOR_TABLES,MAX_PED_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PedestrianDetectorCallPhase", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.14.2.1.3.0' : [ (MAX_DETECTOR_TABLES,MAX_PED_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PedestrianDetectorNoActivity", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.14.2.1.4.0' : [ (MAX_DETECTOR_TABLES,MAX_PED_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PedestrianDetectorMaxPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.14.2.1.5.0' : [ (MAX_DETECTOR_TABLES,MAX_PED_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PedestrianDetectorErraticCounts", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.14.2.1.6.0' : [ (MAX_DETECTOR_TABLES,MAX_PED_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPedestrianDetectorOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.14.2.1.7.0' : [ (MAX_DETECTOR_TABLES,MAX_PED_DETECTORS,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPedestrianDetectorExtraCallPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.14.2.1.8.0' : [ (MAX_DETECTOR_TABLES,MAX_PED_DETECTORS,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPedestrianDetectorCallOverlaps", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.14.2.1.9.0' : [ (MAX_DETECTOR_TABLES,MAX_PED_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PedestrianButtonPushTime", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.14.2.1.10.0' : [ (MAX_DETECTOR_TABLES,MAX_PED_DETECTORS,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtc1202PedestrianDetectorOptions", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.14.4.1.1.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_RW, (0, 1), ASN_INTEGER, "mcAtcPedestrianDetectorControlState", "mandatory" ], #| AF_BU
		
		'1.3.6.1.4.1.1206.3.21.2.14.5.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcPedestrianDataCollectionPeriod", "mandatory" ],
		
    # mcAtcPreempt - McCain		
		'1.3.6.1.4.1.1206.3.21.2.16.1.1.1.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_PED_OVERLAPS), ASN_OCTET_STR, "mcAtcPreemptTrackPedOverlap", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.16.1.1.2.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_PED_OVERLAPS), ASN_OCTET_STR, "mcAtcPreemptDwellPedOverlap", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.16.1.1.3.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, 15), ASN_INTEGER, "mcAtcPreemptOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.16.1.1.4.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_PHASES), ASN_OCTET_STR, "mcAtcPreemptTrackPed", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.16.1.1.5.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_PED_OVERLAPS), ASN_OCTET_STR, "mcAtcPreemptCyclingPedOverlap", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.16.1.1.6.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPreemptExitPedClear", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.16.1.1.7.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPreemptExitYellowChange", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.16.1.1.8.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPreemptExitRedClear", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.16.1.1.9.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPreemptMinTrackGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.16.1.1.10.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPreemptGateDownExtension", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.16.1.1.11.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPreemptExtend", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.16.1.1.12.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcPreemptAdvancedTime", "mandatory" ],
		
    # mcAtcCommunication - McCain		
		'1.3.6.1.4.1.1206.3.21.2.17.1.1.1.0' : [ (NUM_RS232PORTS,0,0,0), ACCESS_P, (1, 8), ASN_INTEGER, "mcAtcSerialProtocol", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.1.1.2.0' : [ (NUM_RS232PORTS,0,0,0), ACCESS_P, (0, MAX_PMPP_ADDRESS), ASN_INTEGER, "mcAtcSerialAddress", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.1.1.3.0' : [ (NUM_RS232PORTS,0,0,0), ACCESS_P, (0, MAX_PMPP_GROUP_ADDRESS), ASN_INTEGER, "mcAtcSerialGroupAddress", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.1.1.4.0' : [ (NUM_RS232PORTS,0,0,0), ACCESS_P, (1, 8), ASN_INTEGER, "mcAtcSerialSpeed", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.1.1.5.0' : [ (NUM_RS232PORTS,0,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "mcAtcSerialParity", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.1.1.6.0' : [ (NUM_RS232PORTS,0,0,0), ACCESS_P, (7, 8), ASN_INTEGER, "mcAtcSerialDataBits", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.1.1.7.0' : [ (NUM_RS232PORTS,0,0,0), ACCESS_P, (1, 2), ASN_INTEGER, "mcAtcSerialStopBits", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.1.1.8.0' : [ (NUM_RS232PORTS,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "mcAtcSerialFlowControl", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.1.1.9.0' : [ (NUM_RS232PORTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcSerialCtsDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.1.1.10.0' : [ (NUM_RS232PORTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcSerialRtsExtend", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.1.1.11.0' : [ (NUM_RS232PORTS,0,0,0), ACCESS_RD, (0, 255), ASN_INTEGER, "mcAtcSerialPortIndex", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.1.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_GAUGE, "mcAtcEthernetIpAddr", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.2.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_GAUGE, "mcAtcEthernetNetmask", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.3.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_GAUGE, "mcAtcEthernetGateway", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.4.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_GAUGE, "mcAtcEthernetDnsServer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.5.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "mcAtcEthernetDhcpMode", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.6.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_GAUGE, "mcAtcEthernetDhcpStart", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.7.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_GAUGE, "mcAtcEthernetDhcpEnd", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.8.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (16, 16), ASN_OCTET_STR, "mcAtcEthernetIpv6Addr", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.9.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, 128), ASN_INTEGER, "mcAtcEthernetIpv6cidr", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.10.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (16, 16), ASN_OCTET_STR, "mcAtcEthernetIpv6gateway", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.11.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (16, 16), ASN_OCTET_STR, "mcAtcEthernetIpv6dnsServer", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.12.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, SIZE_HOSTNAME), ASN_OCTET_STR, "mcAtcEthernetHostname", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.13.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcEthernetNtcipPort", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.14.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (1, 2), ASN_INTEGER, "mcAtcEthernetNtcipMode", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.15.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcEthernetAB3418Port", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.16.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (1, 2), ASN_INTEGER, "mcAtcEthernetAB3418Mode", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.17.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, MAX_PMPP_ADDRESS), ASN_INTEGER, "mcAtcEthernetAB3418Addr", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.18.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, MAX_PMPP_GROUP_ADDRESS), ASN_INTEGER, "mcAtcEthernetAB3418GroupAddr", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.19.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcEthernetP2pPort", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.20.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcEthernetFhpPort", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.21.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcEthernetFhpAddr", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.22.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, MAX_ETHERNET_FHP_CITY_CODE), ASN_INTEGER, "mcAtcEthernetFhpCity", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.2.1.23.0' : [ (NUM_ETHERNETPORTS,0,0,0), ACCESS_P, (0, MAX_FHP_FORWARDS), ASN_OCTET_STR, "u8McAtcEthernetFhpResponseForward", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.17.3.0' : [ (0,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "mcAtcDownloadRequest", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.4.1.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_FHP_FORWARDS), ASN_INTEGER, "mcAtcMaxEthernetFhpForwardingEntries", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.17.4.2.1.1.0' : [ (MAX_FHP_FORWARDS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcEthernetFhpForwardingEntryNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.4.2.1.2.0' : [ (MAX_FHP_FORWARDS,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_GAUGE, "mcAtcEthernetFhpForwardingIpAddress", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.17.4.2.1.3.0' : [ (MAX_FHP_FORWARDS,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcEthernetFhpForwardingPort", "mandatory" ],
		
    # mcAtcTimeSync - McCain		
		'1.3.6.1.4.1.1206.3.21.2.18.1.0' : [ (0,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_GAUGE, "mcAtcNtpIpAddr", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.18.2.0' : [ (0,0,0,0), ACCESS_P, (16, 16), ASN_OCTET_STR, "mcAtcNtpIpv6Addr", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.18.3.0' : [ (0,0,0,0), ACCESS_P, (0, 23), ASN_INTEGER, "mcAtcNtpStartHour", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.18.4.0' : [ (0,0,0,0), ACCESS_P, (0, 59), ASN_INTEGER, "mcAtcNtpStartMinute", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.18.5.0' : [ (0,0,0,0), ACCESS_P2, (0, INTERVAL_HOUR_LIMIT), ASN_INTEGER, "mcAtcNtpIntervalHour", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.18.6.0' : [ (0,0,0,0), ACCESS_P2, (0, INTERVAL_MINUTE_LIMIT), ASN_INTEGER, "mcAtcNtpIntervalMinute", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.18.7.0' : [ (0,0,0,0), ACCESS_P, (0, 23), ASN_INTEGER, "mcAtcGpsStartHour", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.18.8.0' : [ (0,0,0,0), ACCESS_P, (0, 59), ASN_INTEGER, "mcAtcGpsStartMinute", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.18.9.0' : [ (0,0,0,0), ACCESS_P2, (0, INTERVAL_HOUR_LIMIT), ASN_INTEGER, "mcAtcGpsIntervalHour", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.18.10.0' : [ (0,0,0,0), ACCESS_P2, (0, INTERVAL_MINUTE_LIMIT), ASN_INTEGER, "mcAtcGpsIntervalMinute", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.18.11.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcNtpServerOptions", "mandatory" ],
		
    # mcAtcTimebase - McCain		
		'1.3.6.1.4.1.1206.3.21.2.19.1.1.1.0' : [ (MAX_TBC_ACTIONS,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "mcAtcTimebaseDetectorReset", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.19.1.1.2.0' : [ (MAX_TBC_ACTIONS,0,0,0), ACCESS_P, (LOG_MODE_TIMEBASE_NOACTION, LOG_MODE_TIMEBASE_STOP), ASN_INTEGER, "mcAtcTimebaseDetVOSLog", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.19.1.1.3.0' : [ (MAX_TBC_ACTIONS,0,0,0), ACCESS_P, (LOG_MODE_TIMEBASE_NOACTION, LOG_MODE_TIMEBASE_STOP), ASN_INTEGER, "mcAtcTimebaseSpeedTrapLog", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.19.1.1.4.0' : [ (MAX_TBC_ACTIONS,0,0,0), ACCESS_P, (LOG_MODE_TIMEBASE_NOACTION, LOG_MODE_TIMEBASE_STOP), ASN_INTEGER, "mcAtcTimebaseCycleMOELog", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.19.1.1.5.0' : [ (MAX_TBC_ACTIONS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcTimebaseSpecialFunction2", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.19.1.1.6.0' : [ (MAX_TBC_ACTIONS,0,0,0), ACCESS_P, (LOG_MODE_TIMEBASE_NOACTION, LOG_MODE_TIMEBASE_STOP), ASN_INTEGER, "mcAtcTimebaseHRLog", "mandatory" ],
		
    # mcAtcMenuPermissions - McCain		
		'1.3.6.1.4.1.1206.3.21.2.20.1.0' : [ (0,0,0,0), ACCESS_RD, (0, NUM_PERMISSIONS_USERS), ASN_INTEGER, "mcAtcMaxMenuPermissionsUsers", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.20.2.1.1.0' : [ (NUM_PERMISSIONS_USERS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcMenuPermissionsUserNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.20.2.1.2.0' : [ (NUM_PERMISSIONS_USERS,0,0,0), ACCESS_P2, (0, INT16U_MAX - 1), ASN_INTEGER, "mcAtcMenuPermissionsUserID", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.20.2.1.3.0' : [ (NUM_PERMISSIONS_USERS,0,0,0), ACCESS_P2, (0, INT16U_MAX), ASN_INTEGER, "mcAtcMenuPermissionsUserPin", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.20.2.1.4.0' : [ (NUM_PERMISSIONS_USERS,0,0,0), ACCESS_P2, (0, INT16U_MAX), ASN_INTEGER, "mcAtcMenuPermissionsUserAccess", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.20.3.0' : [ (0,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcMenuPermissionsOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.20.4.0' : [ (0,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcMenuPermissionsTimeout", "mandatory" ],
		
    #  mcAtcCic - McCain		
		'1.3.6.1.4.1.1206.3.21.2.21.1.0' : [ (0,0,0,0), ACCESS_RD, (1, 10), ASN_INTEGER, "mcAtcCicStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.21.2.0' : [ (0,0,0,0), ACCESS_RW, (0, 3), ASN_INTEGER, "mcAtcCicMode", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.3.21.2.21.3.0' : [ (0,0,0,0), ACCESS_RW, (0, INT8U_MAX - 5), ASN_INTEGER, "mcAtcCicPatternNumber", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.3.21.2.21.4.0' : [ (0,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCicCycleTime", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.3.21.2.21.5.0' : [ (0,0,0,0), ACCESS_RW, (0, INT8U_MAX - 1), ASN_INTEGER, "mcAtcCicOffsetTime", "mandatory" ], # | AF_BU
		
		'1.3.6.1.4.1.1206.3.21.2.21.6.1.1.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcCicSplitNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.21.6.1.2.0' : [ (MAX_PHASES,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCicSplitTime", "mandatory" ], # | AF_BU
		
		'1.3.6.1.4.1.1206.3.21.2.21.7.0' : [ (0,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "mcAtcRemoteVolumeOccupancyPeriod", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.21.8.0' : [ (0,0,0,0), ACCESS_RW, (0, 3), ASN_INTEGER, "mcAtcCicSyncReferenceMode", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.3.21.2.21.9.0' : [ (0,0,0,0), ACCESS_RW, (0, SECS_PER_DAY), ASN_UNSIGNED, "mcAtcCicSyncReferenceTime", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.3.21.2.21.10.1.1.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCicSplitTimeUsedCurrent", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.21.10.1.2.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCicSplitPhaseStatusCurrent", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.21.10.1.3.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCicSplitTimeUsedLast", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.21.10.1.4.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCicSplitPhaseStatusLast", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.21.11.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCicSplitSequenceNumberCurrent", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.21.12.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcCicSplitSequenceNumberLast", "mandatory" ],
		
    # mcAtcHiResLog - McCain		
		'1.3.6.1.4.1.1206.3.21.2.22.1.0' : [ (0,0,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "mcAtcHiResLogMode", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.22.2.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcHiResLogEventEnable", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.22.3.0' : [ (0,0,0,0), ACCESS_RD, (0, MCCAIN_EVENTS_COUNT), ASN_INTEGER, "mcAtcHiResLogMaxMcCainEvents", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.22.4.1.1.0' : [ (MCCAIN_EVENTS_COUNT,0,0,0), ACCESS_RD, (0, MCCAIN_EVENTS_COUNT), ASN_INTEGER, "mcAtcHiResLogMcCainEventID", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.22.4.1.2.0' : [ (MCCAIN_EVENTS_COUNT,0,0,0), ACCESS_RD, (0, HIRES_DESCRIPTION_LENGTH), ASN_OCTET_STR, "mcAtcHiResLogMcCainEventDescription", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.22.4.1.3.0' : [ (MCCAIN_EVENTS_COUNT,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcHiResLogMcCainEventDataLength", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.22.4.1.4.0' : [ (MCCAIN_EVENTS_COUNT,0,0,0), ACCESS_RD, (0, HIRES_DESCRIPTION_LENGTH ), ASN_OCTET_STR, "mcAtcHiResLogMcCainEventDataDetails", "mandatory" ],
		
    # mcAtcP2p - McCain		
		'1.3.6.1.4.1.1206.3.21.2.23.1.0' : [ (0,0,0,0), ACCESS_RD, (0, NUM_PEER_INPUTS), ASN_INTEGER, "mcAtcP2pMaxDevices", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.23.2.1.1.0' : [ (NUM_PEER_INPUTS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcP2pDeviceNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.23.2.1.2.0' : [ (NUM_PEER_INPUTS,0,0,0), ACCESS_P2, (0, INT32U_MAX), ASN_GAUGE, "mcAtcP2pPeerIpv4Address", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.23.2.1.3.0' : [ (NUM_PEER_INPUTS,0,0,0), ACCESS_P2, (0, INT32U_MAX), ASN_GAUGE, "mcAtcP2pPeerSystemId", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.23.2.1.4.0' : [ (NUM_PEER_INPUTS,0,0,0), ACCESS_P2, (0, INT16U_MAX), ASN_INTEGER, "mcAtcP2pPeerPort", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.23.2.1.5.0' : [ (NUM_PEER_INPUTS,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcP2pPeerMessageTimeout", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.23.2.1.6.0' : [ (NUM_PEER_INPUTS,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcP2pPeerRetries", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.23.2.1.7.0' : [ (NUM_PEER_INPUTS,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcP2pPeerHeartbeatTime", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.23.3.0' : [ (0,0,0,0), ACCESS_RD, (0, NUM_PEER_INPUT_FUNCTIONS), ASN_INTEGER, "mcAtcP2pMaxFunctions", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.23.4.1.1.0' : [ (NUM_PEER_INPUT_FUNCTIONS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcP2pFunctionNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.23.4.1.2.0' : [ (NUM_PEER_INPUT_FUNCTIONS,0,0,0), ACCESS_P2, (0, NUM_PEER_INPUTS), ASN_INTEGER, "mcAtcP2pFunctionDeviceNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.23.4.1.3.0' : [ (NUM_PEER_INPUT_FUNCTIONS,0,0,0), ACCESS_P2, (1, IOGI_NUMIDS - 1), ASN_INTEGER, "mcAtcP2pFunctionRemoteFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.23.4.1.4.0' : [ (NUM_PEER_INPUT_FUNCTIONS,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcP2pFunctionRemoteFunctionIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.23.4.1.5.0' : [ (NUM_PEER_INPUT_FUNCTIONS,0,0,0), ACCESS_P2, (1, IOGO_NUMIDS - 1), ASN_INTEGER, "mcAtcP2pFunctionLocalFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.23.4.1.6.0' : [ (NUM_PEER_INPUT_FUNCTIONS,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcAtcP2pFunctionLocalFunctionIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.23.4.1.7.0' : [ (NUM_PEER_INPUT_FUNCTIONS,0,0,0), ACCESS_P2, (0, 1), ASN_INTEGER, "mcAtcP2pFunctionDefaultState", "mandatory" ],
		
    # mcAtcSpat - McCain		
		'1.3.6.1.4.1.1206.3.21.2.24.1.1.0' : [ (0,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcSpatOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.2.0' : [ (0,0,0,0), ACCESS_P2, (0, INT32U_MAX), ASN_GAUGE, "mcAtcSpatDestinationAddrIpv4", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.3.0' : [ (0,0,0,0), ACCESS_P2, (16, 16), ASN_OCTET_STR, "mcAtcSpatDestinationAddrIpv6", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.4.0' : [ (0,0,0,0), ACCESS_P2, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpatDestinationPort", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.24.1.5.1.1.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcSpatPhaseTimeToChangeNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.5.1.2.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpatVehMinTimeToChange", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.5.1.3.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpatVehMaxTimeToChange", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.5.1.4.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpatPedMinTimeToChange", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.5.1.5.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpatPedMaxTimeToChange", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.24.1.6.1.1.0' : [ (MAX_OVERLAPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcSpatOvlpTimeToChangeNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.6.1.2.0' : [ (MAX_OVERLAPS,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpatOvlpMinTimeToChange", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.6.1.3.0' : [ (MAX_OVERLAPS,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpatOvlpMaxTimeToChange", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.24.1.7.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpatIntersectionStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.8.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpatDiscontinuousChangeFlag", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.9.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpatMessageSeqCounter", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.10.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_SPAT_DESTINATIONS), ASN_INTEGER, "mcAtcMaxSpatDestinations", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.24.1.11.1.1.0' : [ (MAX_SPAT_DESTINATIONS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcAtcSpatDestNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.11.1.2.0' : [ (MAX_SPAT_DESTINATIONS,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "mcAtcSpatDestOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.11.1.3.0' : [ (MAX_SPAT_DESTINATIONS,0,0,0), ACCESS_P2, (0, INT32U_MAX), ASN_UNSIGNED, "mcAtcSpatDestAddrIpv4", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.11.1.4.0' : [ (MAX_SPAT_DESTINATIONS,0,0,0), ACCESS_P2, (16, 16), ASN_OCTET_STR, "mcAtcSpatDestAddrIpv6", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.24.1.11.1.5.0' : [ (MAX_SPAT_DESTINATIONS,0,0,0), ACCESS_P2, (0, INT16U_MAX), ASN_INTEGER, "mcAtcSpatDestPort", "mandatory" ],
		
    # mcAtcBoston - McCain		
		'1.3.6.1.4.1.1206.3.21.2.25.1.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_BOSTON_SETTINGS), ASN_INTEGER, "mcAtcBostonMaxSettings", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.25.2.1.1.0' : [ (MAX_BOSTON_SETTINGS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcBostonSettingsNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.25.2.1.2.0' : [ (MAX_BOSTON_SETTINGS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcBostonPhaseMap", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.25.2.1.3.0' : [ (MAX_BOSTON_SETTINGS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcBostonDetMap", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.25.2.1.4.0' : [ (MAX_BOSTON_SETTINGS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcBostonSysDetMap", "mandatory" ],
		
    # mcAtcBlocksDefinitions - McCain		
		'1.3.6.1.4.1.1206.3.21.2.26.1.0' : [ (0,0,0,0), ACCESS_RD, (0, NUM_STD_ASC_BLKS), ASN_INTEGER, "mcAtcMaxStandardBlocksDefinitions", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.26.2.1.1.0' : [ (NUM_STD_ASC_BLKS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcStandardBLocksDefinitionsNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.26.2.1.2.0' : [ (NUM_STD_ASC_BLKS,0,0,0), ACCESS_RD, (0, MAX_BLOCK_DEFINITION), ASN_OCTET_STR, "mcAtcStandardBlocksDefinition", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.26.3.0' : [ (0,0,0,0), ACCESS_RD, (0, NUM_CUSTOM_ASC_BLKS), ASN_INTEGER, "mcAtcMaxOmniBlocksDefinitions", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.26.4.1.1.0' : [ (NUM_CUSTOM_ASC_BLKS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcOmniBLocksDefinitionsNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.26.4.1.2.0' : [ (NUM_CUSTOM_ASC_BLKS,0,0,0), ACCESS_RD, (0, MAX_BLOCK_DEFINITION), ASN_OCTET_STR, "mcAtcOmniBlocksDefinition", "mandatory" ],
		
    # mcAtcSecurity - McCain		
		'1.3.6.1.4.1.1206.3.21.2.27.1.1.0' : [ (0,0,0,0), ACCESS_P, (1, INT8U_MAX), ASN_INTEGER, "mcAtcSecUserAuthTries", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.27.1.2.0' : [ (0,0,0,0), ACCESS_P, (1, INT8U_MAX), ASN_INTEGER, "mcAtcSecUserAuthTimeWait", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.27.1.3.0' : [ (0,0,0,0), ACCESS_P, (1, INT8U_MAX), ASN_INTEGER, "mcAtcSecUserAuthTriesBlock", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.27.1.4.0' : [ (0,0,0,0), ACCESS_P, (1, INT8U_MAX), ASN_INTEGER, "mcAtcSecUserSessionTimeout", "optional" ],
		'1.3.6.1.4.1.1206.3.21.2.27.1.5.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_SECURITY_USERS), ASN_INTEGER, "mcAtcSecUserMaxUsers", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.27.1.6.1.1.0' : [ (MAX_SECURITY_USERS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcAtcSecUserNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.27.1.6.1.2.0' : [ (MAX_SECURITY_USERS,0,0,0), ACCESS_NONE, (0, SIZE_USERNAME), ASN_OCTET_STR, "mcAtcSecUserName", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.27.1.6.1.3.0' : [ (MAX_SECURITY_USERS,0,0,0), ACCESS_NONE, (0, SIZE_USERKEY), ASN_OCTET_STR, "mcAtcSecUserKey", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.27.1.6.1.4.0' : [ (MAX_SECURITY_USERS,0,0,0), ACCESS_NONE, (0, SIZE_OCTET_STRING_CONFIG), ASN_OCTET_STR, "mcAtcSecUserECabinetStatus", "optional" ],
		
    # mcAtcDayOfTheWeek - McCain		
		'1.3.6.1.4.1.1206.3.21.2.28.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_DOW_SCHEDULES), ASN_INTEGER, "mcAtcMaxDayOfWeekCurrentSchedule", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.28.2.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_DOW_SCHEDULES), ASN_INTEGER, "mcAtcMaxDayOfWeekScheduleEntries", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.28.3.1.1.0' : [ (MAX_DOW_SCHEDULES,0,0,0), ACCESS_RD, (1, MAX_DOW_SCHEDULES), ASN_INTEGER, "mcAtcDOWScheduleNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.28.3.1.2.0' : [ (MAX_DOW_SCHEDULES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "mcAtcDayOfWeekDay", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.28.3.1.3.0' : [ (MAX_DOW_SCHEDULES,0,0,0), ACCESS_P, (0, 23), ASN_INTEGER, "mcAtcDayOfWeekHour", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.28.3.1.4.0' : [ (MAX_DOW_SCHEDULES,0,0,0), ACCESS_P, (0, 59), ASN_INTEGER, "mcAtcDayOfWeekMinute", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.28.3.1.5.0' : [ (MAX_DOW_SCHEDULES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "mcAtcDayOfWeekFunctionSets", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.28.4.0' : [ (0,0,0,0), ACCESS_RD, (1, DOWFUNC_NUMFUNCTIONS), ASN_INTEGER, "mcAtcMaxDOWFunctions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.28.5.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_DOW_FUNCTION_SETS), ASN_INTEGER, "mcAtcMaxDOWFunctionSets", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.2.28.6.1.1.0' : [ (MAX_DOW_FUNCTION_SETS,0,0,0), ACCESS_RD, (1, MAX_DOW_FUNCTION_SETS), ASN_INTEGER, "mcAtcDOWFunctionNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.28.6.1.2.0' : [ (MAX_DOW_FUNCTION_SETS,0,0,0), ACCESS_P2, (0, MAX_DOW_FUNCTION_OCTET_LEN), ASN_OCTET_STR, "mcAtcDOWFunctions", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.2.28.6.1.3.0' : [ (MAX_DOW_FUNCTION_SETS,0,0,0), ACCESS_P2, (0, MAX_DOW_FUNCTION_VALUES_OCTET_LEN), ASN_OCTET_STR, "mcAtcDOWFunctionValues", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.1.1.7.1.1.0' : [ (0,0,0,0), ACCESS_RD, (484, SIZE_COMMSBLOCK), ASN_INTEGER, "snmpmaxPacketSize", "mandatory" ],

    #------------------------------------------------------------------- MCRMCIOMAPPING-------------------------------------------------------------------------		
    # mcRmcNemaIoInputs		
		'1.3.6.1.4.1.1206.3.21.3.2.3.1.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcMaxNemaIoInputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.3.2.1.1.0' : [ (NUM_NEMA_INBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcNemaIoInputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.3.2.1.2.0' : [ (NUM_NEMA_INBITS,0,0,0), ACCESS_P2, (1,8), ASN_INTEGER, "mcRmcNemaIoInputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.3.2.1.3.0' : [ (NUM_NEMA_INBITS,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcRmcNemaIoInputIndex ", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.3.2.1.4.0' : [ (NUM_NEMA_INBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcRmcNemaIoInputRowLabel", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.3.3.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcMaxNemaIoOutputs ", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.3.4.1.1.0' : [ (NUM_NEMA_OUTBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcNemaIoOutputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.3.4.1.2.0' : [ (NUM_NEMA_OUTBITS,0,0,0), ACCESS_P2, (1,7), ASN_INTEGER, "mcRmcNemaIoOutputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.3.4.1.3.0' : [ (NUM_NEMA_OUTBITS,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcRmcNemaIoOutputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.3.4.1.4.0' : [ (NUM_NEMA_OUTBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcRmcNemaIoOutputRowLabel", "mandatory" ],
		
    # mcRmcTs2IoMapping		
		'1.3.6.1.4.1.1206.3.21.3.2.4.1.0' : [ (0,0,0,0), ACCESS_RD, (1, RM_NUM_TS2_BIUS), ASN_INTEGER, "mcRmcMaxTs2Bius", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.4.2.0' : [ (0,0,0,0), ACCESS_RD, (1, RM_NUM_TS2_BIU_INPUTS), ASN_INTEGER, "mcRmcMaxTs2BiuInputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.4.3.1.1.0' : [ (RM_NUM_TS2_BIUS,RM_NUM_TS2_BIU_INPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcTs2IoBiuInNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.4.3.1.2.0' : [ (RM_NUM_TS2_BIUS,RM_NUM_TS2_BIU_INPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcTs2IoInputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.4.3.1.3.0' : [ (RM_NUM_TS2_BIUS,RM_NUM_TS2_BIU_INPUTS,0,0), ACCESS_P2, (1, IOI_NUMIDS - 1), ASN_INTEGER, "mcRmcTs2IoInputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.4.3.1.4.0' : [ (RM_NUM_TS2_BIUS,RM_NUM_TS2_BIU_INPUTS,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcRmcTs2IoInputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.4.3.1.5.0' : [ (RM_NUM_TS2_BIUS,RM_NUM_TS2_BIU_INPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcRmcTs2IoInputRowLabel", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.4.4.0' : [ (0,0,0,0), ACCESS_RD, (1, RM_NUM_TS2_BIU_OUTPUTS), ASN_INTEGER, "mcRmcMaxTs2IoBiuOutputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.4.5.1.1.0' : [ (RM_NUM_TS2_BIUS,RM_NUM_TS2_BIU_OUTPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcTs2IoBiuOutNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.4.5.1.2.0' : [ (RM_NUM_TS2_BIUS,RM_NUM_TS2_BIU_OUTPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcTs2IoOutputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.4.5.1.3.0' : [ (RM_NUM_TS2_BIUS,RM_NUM_TS2_BIU_OUTPUTS,0,0), ACCESS_P2, (1, IOO_NUMIDS - 1), ASN_INTEGER, "mcRmcTs2IoOutputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.4.5.1.4.0' : [ (RM_NUM_TS2_BIUS,RM_NUM_TS2_BIU_OUTPUTS,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcRmcTs2IoOutputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.4.5.1.5.0' : [ (RM_NUM_TS2_BIUS,RM_NUM_TS2_BIU_OUTPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcRmcTs2IoOutputRowLabel", "mandatory" ],
		
    # mcRmcFioIoMapping		
		'1.3.6.1.4.1.1206.3.21.3.2.5.1.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_2070_2A_INBITS), ASN_INTEGER, "mcRmcMaxFioIoInputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.5.2.1.1.0' : [ (NUM_2070_2A_INBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcFioIoInputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.5.2.1.2.0' : [ (NUM_2070_2A_INBITS,0,0,0), ACCESS_P2, (1, IOI_NUMIDS - 1), ASN_INTEGER, "mcRmcFioIoInputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.5.2.1.3.0' : [ (NUM_2070_2A_INBITS,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcRmcFioIoInputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.5.2.1.4.0' : [ (NUM_2070_2A_INBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcRmcFioIoInputRowLabel", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.5.3.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_2070_2A_OUTBITS), ASN_INTEGER, "mcRmcMaxFioIoOutputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.5.4.1.1.0' : [ (NUM_2070_2A_OUTBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcFioIoOutputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.5.4.1.2.0' : [ (NUM_2070_2A_OUTBITS,0,0,0), ACCESS_P2, (1, IOO_NUMIDS - 1), ASN_INTEGER, "mcRmcFioIoOutputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.5.4.1.3.0' : [ (NUM_2070_2A_OUTBITS,0,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcRmcFioIoOutputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.5.4.1.4.0' : [ (NUM_2070_2A_OUTBITS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcRmcFioIoOutputRowLabel", "mandatory" ],
		
    # mcRmcItsIoMapping		
		'1.3.6.1.4.1.1206.3.21.3.2.6.1.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_ITS_SIUS), ASN_INTEGER, "mcRmcMaxItsSius", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.6.2.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_ITS_SIU_INPUTS), ASN_INTEGER, "mcRmcMaxItsSiuInputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.6.3.1.1.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_INPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcItsIoSiuInNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.6.3.1.2.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_INPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcItsIoInputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.6.3.1.3.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_INPUTS,0,0), ACCESS_P2, (1, IOI_NUMIDS - 1), ASN_INTEGER, "mcRmcItsIoInputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.6.3.1.4.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_INPUTS,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcRmcItsIoInputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.6.3.1.5.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_INPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcRmcItsIoInputRowLabel", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.6.4.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_ITS_SIU_OUTPUTS), ASN_INTEGER, "mcRmcMaxItsIoSiuOutputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.6.5.1.1.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_OUTPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcItsIoSiuOutNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.6.5.1.2.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_OUTPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcItsIoOutputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.6.5.1.3.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_OUTPUTS,0,0), ACCESS_P2, (1, IOO_NUMIDS - 1), ASN_INTEGER, "mcRmcItsIoOutputFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.6.5.1.4.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_OUTPUTS,0,0), ACCESS_P2, (1, INT8U_MAX), ASN_INTEGER, "mcRmcItsIoOutputIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.6.5.1.5.0' : [ (NUM_ITS_SIUS,NUM_ITS_SIU_OUTPUTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_OCTET_STR, "mcRmcItsIoOutputRowLabel", "mandatory" ],
		
    # mcRmcItsDevicesIoMapping		
		'1.3.6.1.4.1.1206.3.21.3.2.7.1.0' : [ (0,0,0,0), ACCESS_RD, (1, RMC_MAX_ITS_DEVICES), ASN_INTEGER, "mcRmcMaxItsDevices", "mandatory" ],
		
		'1.3.6.1.4.1.1206.3.21.3.2.7.2.1.1.0' : [ (RMC_MAX_ITS_DEVICES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcItsDeviceNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.7.2.1.2.0' : [ (RMC_MAX_ITS_DEVICES,0,0,0), ACCESS_P, (0, 2), ASN_INTEGER, "mcRmcItsDevicePresent", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.7.2.1.4.0' : [ (RMC_MAX_ITS_DEVICES,0,0,0), ACCESS_RD, (1, 3), ASN_INTEGER, "mcRmcItsDeviceStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.3.21.3.2.7.2.1.5.0' : [ (RMC_MAX_ITS_DEVICES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "mcRmcItsDeviceFaultFrame", "mandatory" ],
		
		# Standar Ramp meter Blocks
		'1.3.6.1.4.1.1206.3.21.3.3.1.0' : [ (0,0,0,0), ACCESS_RD, (0, NUM_STD_RAMP_ASC_BLKS), ASN_INTEGER, "mcRmcMaxStandardRampBlockDefinitions", "mandatory" ],
    '1.3.6.1.4.1.1206.3.21.3.3.2.1.1.0' : [ (NUM_STD_RAMP_ASC_BLKS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcStandardRampBlocksDefinitionNumber", "mandatory" ],
    '1.3.6.1.4.1.1206.3.21.3.3.2.1.2.0.' : [ (NUM_STD_RAMP_ASC_BLKS,0,0,0), ACCESS_RD, (0, MAX_BLOCK_DEFINITION), ASN_OCTET_STR, "mcRmcStandardRampBlocksDefinition", "mandatory" ],

		# Omni Ramp meter Block
		'1.3.6.1.4.1.1206.3.21.3.3.3.0' : [ (0,0,0,0), ACCESS_RD, (0, NUM_CUSTOM_RAMP_ASC_BLKS), ASN_INTEGER, "mcRmcMaxOmniRampBlockDefinitions", "mandatory" ],
    '1.3.6.1.4.1.1206.3.21.3.3.4.1.1.0' : [ (NUM_CUSTOM_RAMP_ASC_BLKS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "mcRmcOmniRampBlocksDefinitionNumber", "mandatory" ],
    '1.3.6.1.4.1.1206.3.21.3.3.4.1.2.0' : [ (NUM_CUSTOM_RAMP_ASC_BLKS,0,0,0), ACCESS_RD, (0, MAX_BLOCK_DEFINITION), ASN_OCTET_STR, "mcRmcOmniRampBlocksDefinition", "mandatory" ],

		# Omni Ramp Aux Outputs
		'1.3.6.1.4.1.1206.3.21.3.4.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_RAMP_AUX_OUTPUTS), ASN_INTEGER, "mcRmcMaxAuxOutputs", "mandatory" ],
    '1.3.6.1.4.1.1206.3.21.3.4.2.1.1.0' : [ (MAX_RAMP_AUX_OUTPUTS,0,0,0), ACCESS_RD, (1, MAX_RAMP_AUX_OUTPUTS), ASN_INTEGER, "mcRmcAuxOutputNumber", "mandatory" ],
    '1.3.6.1.4.1.1206.3.21.3.4.2.1.2.0' : [ (MAX_RAMP_AUX_OUTPUTS,0,0,0), ACCESS_RW, (0, 1), ASN_INTEGER, "mcRmcAuxOutputState", "mandatory" ],
    '1.3.6.1.4.1.1206.3.21.3.4.2.1.3.0' : [ (MAX_RAMP_AUX_OUTPUTS,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "mcRmcAuxOutputOnDelay", "mandatory" ],
    '1.3.6.1.4.1.1206.3.21.3.4.2.1.4.0' : [ (MAX_RAMP_AUX_OUTPUTS,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "mcRmcAuxOutputOffDelay", "mandatory" ],

		# Omni Ramp Queue
 		'1.3.6.1.4.1.1206.3.21.3.5.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_QUEUES), ASN_INTEGER, "mcRmcMaxRampQueues", "mandatory" ],
    '1.3.6.1.4.1.1206.3.21.3.5.2.1.1.0' : [ (MAX_QUEUES,0,0,0), ACCESS_RD, (1, MAX_QUEUES), ASN_INTEGER, "mcRmcQueueStatusNumber", "mandatory" ],
    '1.3.6.1.4.1.1206.3.21.3.5.2.1.2.0' : [ (MAX_QUEUES,0,0,0), ACCESS_RD, (0, 1), ASN_INTEGER, "mcRmcQueueStatusState", "mandatory" ],

    # stmp - NTCIP 1103		

		'1.3.6.1.4.1.1206.4.1.1.7.1.1.0' : [ (0,0,0,0), ACCESS_RD, (484, SIZE_COMMSBLOCK), ASN_INTEGER, "snmpmaxPacketSize", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.1.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinPkts", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.2.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutPkts", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.6.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinParseErrs", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.8.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinTooBigs", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.9.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinNoSuchNames", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.10.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinBadValues", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.11.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinReadOnlys", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.12.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinGenErrs", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.15.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinGetRequests", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.16.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinGetNexts", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.17.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinSetRequests", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.18.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinGetResponses", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.20.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutTooBigs", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.21.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutNoSuchNames", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.22.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutBadValues", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.23.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutReadOnly", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.24.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutGenError", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.25.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutGetRequests", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.26.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutGetNexts", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.27.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutSetRequests", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.28.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutGetResponses", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.31.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinSetRequestsNoReply", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.32.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinSetResponses", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.33.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpinErrorResponses", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.34.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutSetRequestsNoReply", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.35.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutSetResponses", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.3.1.36.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "stmpoutErrorResponses", "mandatory" ],
		
    # LogicalName - NTCIP 1103		
		'1.3.6.1.4.1.1206.4.1.1.7.4.1.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_LOGNAMETRANS), ASN_INTEGER, "logicalNameTranslationTablemaxEntries", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.1.1.7.4.2.1.1.0' : [ (NUM_LOGNAMETRANS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "logicalNameTranslationindex", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.4.2.1.2.0' : [ (NUM_LOGNAMETRANS,0,0,0), ACCESS_RW, (0, SIZE_LOGNAMETRANS), ASN_OCTET_STR, "logicalNameTranslationlogicalName", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.4.2.1.3.0' : [ (NUM_LOGNAMETRANS,0,0,0), ACCESS_RW, (4, 4), ASN_IPADDRESS, "logicalNameTranslationnetworkAddress", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.1.7.4.2.1.4.0' : [ (NUM_LOGNAMETRANS,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "logicalNameTranslationstatus", "mandatory" ],
		
    # hdlcGroupAddress - NTCIP 1201		
		'1.3.6.1.4.1.1206.4.1.2.3.1.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_HDLCGRPADDR), ASN_INTEGER, "maxGroupAddresses", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.2.3.2.1.1.0' : [ (NUM_HDLCGRPADDR,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "hdlcGroupAddressIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.2.3.2.1.3.0' : [ (NUM_HDLCGRPADDR,0,0,0), ACCESS_P, (0, 62), ASN_INTEGER, "hdlcGroupAddressNumber", "mandatory" ],
		
    # dynObjMgmt		
		'1.3.6.1.4.1.1206.4.1.3.1.1.1.0' : [ (MAX_DYNOBJS,MAX_DYNOBJ_VARS,0,0), ACCESS_RD, (1, MAX_DYNOBJS), ASN_INTEGER, "dynObjNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.3.1.1.2.0' : [ (MAX_DYNOBJS,MAX_DYNOBJ_VARS,0,0), ACCESS_RD, (1, 255), ASN_INTEGER, "dynObjIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.3.1.1.3.0' : [ (MAX_DYNOBJS,MAX_DYNOBJ_VARS,0,0), ACCESS_P, (0, SIZE_DYNOBJ_VAR), ASN_OBJECT_ID, "dynObjVariable", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.3.3.1.1.0' : [ (MAX_DYNOBJS,0,0,0), ACCESS_P, (0, SIZE_DYNCFG_OWNER), ASN_OCTET_STR, "dynObjConfigOwner", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.3.3.1.2.0' : [ (MAX_DYNOBJS,0,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "dynObjConfigStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.1.3.4.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_DYNOBJ_VARS), ASN_INTEGER, "dynObjDefTableMaxEntries", "mandatory" ],
		
    # phase - NTCIP 1202		
		'1.3.6.1.4.1.1206.4.2.1.1.1.0' : [ (0,0,0,0), ACCESS_RD, (2, MAX_PHASES), ASN_INTEGER, "maxPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.1.0' : [ (MAX_PHASES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "phaseNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.2.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseWalk", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.3.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phasePedestrianClear", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.4.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseMinimumGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.5.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phasePassage", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.6.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseMaximum1", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.7.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseMaximum2", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.8.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseYellowChange", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.9.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseRedClear", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.10.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseRedRevert", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.11.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseAddedInitial", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.12.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseMaximumInitial", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.13.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseTimeBeforeReduction", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.14.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseCarsBeforeReduction", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.15.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseTimeToReduce", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.16.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseReduceBy", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.17.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseMinimumGap", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.18.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseDynamicMaxLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.19.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phaseDynamicMaxStep", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.20.0' : [ (MAX_PHASES,0,0,0), ACCESS_P2, (2, 6), ASN_INTEGER, "phaseStartup", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.21.0' : [ (MAX_PHASES,0,0,0), ACCESS_P2, (0, INT16U_MAX), ASN_INTEGER, "phaseOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.22.0' : [ (MAX_PHASES,0,0,0), ACCESS_P2, (0, INT8U_MAX), ASN_INTEGER, "phaseRing", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.23.0' : [ (MAX_PHASES,0,0,0), ACCESS_P2, (0, 16), ASN_OCTET_STR, "phaseConcurrency", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.24.0' : [ (MAX_PHASES,0,0,0), ACCESS_RW, (0, 6000), ASN_INTEGER, "phaseMaximum3", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.25.0' : [ (MAX_PHASES,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "phaseYellowandRedChangeTimeBeforeEndPedClear", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.26.0' : [ (MAX_PHASES,0,0,0), ACCESS_RW, (1, INT8U_MAX), ASN_INTEGER, "phasePedWalkService", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.27.0' : [ (MAX_PHASES,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "phaseDontWalkRevert", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.28.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phasePedAlternateClearance", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.29.0' : [ (MAX_PHASES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "phasePedAlternateWalk", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.30.0' : [ (MAX_PHASES,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "phasePedAdvanceWalkTime", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.31.0' : [ (MAX_PHASES,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "phasePedDelayTime", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.32.0' : [ (MAX_PHASES,0,0,0), ACCESS_RW, (0, 128), ASN_INTEGER, "phaseAdvWarnGrnStartTime", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.33.0' : [ (MAX_PHASES,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "phaseAdvWarnRedStartTime", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.1.2.1.34.0' : [ (MAX_PHASES,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "phaseAltMinTimeTransition", "optional" ],
		
		'1.3.6.1.4.1.1206.4.2.1.1.3.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_PHASEGROUPS), ASN_INTEGER, "maxPhaseGroups", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.1.4.1.1.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "phaseStatusGroupNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.4.1.2.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "phaseStatusGroupReds", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.4.1.3.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "phaseStatusGroupYellows", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.4.1.4.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "phaseStatusGroupGreens", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.4.1.5.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "phaseStatusGroupDontWalks", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.4.1.6.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "phaseStatusGroupPedClears", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.4.1.7.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "phaseStatusGroupWalks", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.4.1.8.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "phaseStatusGroupVehCalls", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.4.1.9.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "phaseStatusGroupPedCalls", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.4.1.10.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "phaseStatusGroupPhaseOns", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.4.1.11.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "phaseStatusGroupPhaseNexts", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.1.5.1.1.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "phaseControlGroupNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.1.5.1.2.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "phaseControlGroupPhaseOmit", "mandatory" ], # |F_BU
		'1.3.6.1.4.1.1206.4.2.1.1.5.1.3.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "phaseControlGroupPedOmit", "mandatory" ], # |F_BU
		'1.3.6.1.4.1.1206.4.2.1.1.5.1.4.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "phaseControlGroupHold", "mandatory" ], # |F_BU
		'1.3.6.1.4.1.1206.4.2.1.1.5.1.5.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "phaseControlGroupForceOff", "mandatory" ], # |F_BU
		'1.3.6.1.4.1.1206.4.2.1.1.5.1.6.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "phaseControlGroupVehCall", "mandatory" ], # |F_BU
		'1.3.6.1.4.1.1206.4.2.1.1.5.1.7.0' : [ (MAX_PHASEGROUPS,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "phaseControlGroupPedCall", "mandatory" ], # |F_BU
		
    # detector - - NTCIP 1202		
		'1.3.6.1.4.1.1206.4.2.1.2.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_DETECTORS), ASN_INTEGER, "maxVehicleDetectors", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.1.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "vehicleDetectorNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.2.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorOptions", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.4.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorCallPhase", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.5.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorSwitchPhase", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.6.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, 2550), ASN_INTEGER, "vehicleDetectorDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.7.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorExtend", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.8.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorQueueLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.9.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorNoActivity", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.10.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorMaxPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.11.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorErraticCounts", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.12.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorFailTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.13.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorAlarms", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.14.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorReportedAlarms", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.15.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RW, (0, 1), ASN_INTEGER, "vehicleDetectorReset", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.16.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RW, (0, (0x01 | 0x02)), ASN_INTEGER, "vehicleDetectorOptions2", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.17.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RW, (0, MAX_DETECTORS), ASN_INTEGER, "vehicleDetectorPairedDetector", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.18.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RW, (0, INT16U_MAX), ASN_INTEGER, "vehicleDetectorPairedDetectorSpacing", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.19.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, 4000), ASN_INTEGER, "vehicleDetectorAvgVehicleLength", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.20.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "vehicleDetectorLength", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.2.1.21.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_P, (0, 4), ASN_INTEGER, "vehicleDetectorTravelMode", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.3.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_DETGROUPS), ASN_INTEGER, "maxVehicleDetectorStatusGroups", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.4.1.1.0' : [ (MAX_DETGROUPS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "vehicleDetectorStatusGroupNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.4.1.2.0' : [ (MAX_DETGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorStatusGroupActive", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.4.1.3.0' : [ (MAX_DETGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorStatusGroupAlarms", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.5.1.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "volumeOccupancySequence", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.5.2.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "volumeOccupancyPeriod", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.5.3.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "activeVolumeOccupancyDetectors", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.5.4.1.1.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "detectorVolume", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.5.4.1.2.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "detectorOccupancy", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.5.4.1.3.0' : [ (MAX_DETECTORS,0,0,0), ACCESS_RD, (0, 511), ASN_INTEGER, "detectorAvgSpeed", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.5.5.0' : [ (0,0,0,0), ACCESS_RW, (0, INT16U_MAX), ASN_INTEGER, "volumeOccupancyPeriodV3", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.5.6.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "detectorSampleTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.5.7.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "detectorSampleDuration", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.6.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_PED_DETECTORS), ASN_INTEGER, "maxPedestrianDetectors", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.7.1.1.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.7.1.2.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorCallPhase", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.7.1.3.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorNoActivity", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.7.1.4.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorMaxPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.7.1.5.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorErraticCounts", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.7.1.6.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorAlarms", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.7.1.7.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_RW, (0, 1), ASN_INTEGER, "pedestrianDetectorReset", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.2.7.1.8.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "pedestrianButtonPushTime", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.2.7.1.9.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorOptions", "optional" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.8.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_PEDGROUPS), ASN_INTEGER, "maxPedestrianDetectorGroups", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.9.1.1.0' : [ (MAX_PEDGROUPS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorStatusGroupNumber", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.2.9.1.2.0' : [ (MAX_PEDGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorStatusGroupActive", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.2.9.1.3.0' : [ (MAX_PEDGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorStatusGroupAlarms", "optional" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.10.1.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorSequence", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.10.2.0' : [ (0,0,0,0), ACCESS_RW, (0, INT16U_MAX), ASN_INTEGER, "pedestrianDetectorPeriod", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.10.3.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "activePedestrianDetectors", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.10.4.1.1.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorVolume", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.10.4.1.2.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorActuations", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.10.4.1.3.0' : [ (MAX_PED_DETECTORS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorServices", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.10.5.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "pedestrianDetectorSampleTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.10.6.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "pedestrianDetectorSampleDuration", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.11.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_DETECTORS / 8), ASN_INTEGER, "maxVehicleDetectorControlGroups", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.2.12.1.1.0' : [ (MAX_DETECTORS / 8,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "vehicleDetectorControlGroupNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.12.1.2.0' : [ (MAX_DETECTORS / 8,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "vehicleDetectorControlGroupActuation", "mandatory" ], #  | AF_BU
		
		'1.3.6.1.4.1.1206.4.2.1.2.13.1.1.0' : [ (MAX_PEDGROUPS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorControlGroupNumber ", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.2.13.1.2.0' : [ (MAX_PEDGROUPS,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "pedestrianDetectorControlGroupActuation ", "mandatory" ],  # | AF_BU
		
    # Unit - - NTCIP 1202		
		'1.3.6.1.4.1.1206.4.2.1.3.1.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "unitStartUpFlash", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.2.0' : [ (0,0,0,0), ACCESS_P, (1, 2), ASN_INTEGER, "unitAutoPedestrianClear", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.3.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "unitBackupTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.4.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "unitRedRevert", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.5.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "unitControlStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.6.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "unitFlashStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.7.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "unitAlarmStatus2", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.8.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "unitAlarmStatus1", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.9.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "shortAlarmStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.10.0' : [ (0,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "unitControl", "mandatory" ],  #| AF_BU
		'1.3.6.1.4.1.1206.4.2.1.3.11.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_ALARMGROUPS), ASN_INTEGER, "maxAlarmGroups", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.3.12.1.1.0' : [ (MAX_ALARMGROUPS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "alarmGroupNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.12.1.2.0' : [ (MAX_ALARMGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "alarmGroupState", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.3.13.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_SPECIALFUNCS), ASN_INTEGER, "maxSpecialFunctionOutputs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.3.14.1.1.0' : [ (MAX_SPECIALFUNCS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "specialFunctionOutputNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.14.1.3.0' : [ (MAX_SPECIALFUNCS,0,0,0), ACCESS_RW, (0, 1), ASN_INTEGER, "specialFunctionOutputControl", "mandatory" ], #  | AF_BU
		'1.3.6.1.4.1.1206.4.2.1.3.14.1.4.0' : [ (MAX_SPECIALFUNCS,0,0,0), ACCESS_RD, (0, 1), ASN_INTEGER, "specialFunctionOutputStatus", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.3.15.0' : [ (0,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "unitMCETimeout", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.16.0' : [ (0,0,0,0), ACCESS_RW, (0, 1), ASN_INTEGER, "unitMCEIntAdv", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.18.0' : [ (0,0,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "unitStartupFlashMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.3.19.0' : [ (0,0,0,0), ACCESS_RW, (0, 16777216), ASN_UNSIGNED, "unitUserDefinedBackupTime", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.3.27.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "unitAlarmStatus4", "optional" ],
		
    # Coord - NTCIP 1202		
		'1.3.6.1.4.1.1206.4.2.1.4.1.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "coordOperationalMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.2.0' : [ (0,0,0,0), ACCESS_P, (2, 5), ASN_INTEGER, "coordCorrectionMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.3.0' : [ (0,0,0,0), ACCESS_P, (2, 4), ASN_INTEGER, "coordMaximumMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.4.0' : [ (0,0,0,0), ACCESS_P, (2, 3), ASN_INTEGER, "coordForceMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.5.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_PATTERNS), ASN_INTEGER, "maxPatterns", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.6.0' : [ (0,0,0,0), ACCESS_RD, (0, 2), ASN_INTEGER, "patternTableType", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.4.7.1.1.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "patternNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.7.1.2.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "patternCycleTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.7.1.3.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "patternOffsetTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.7.1.4.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, MAX_SPLITS), ASN_INTEGER, "patternSplitNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.7.1.5.0' : [ (MAX_PATTERNS,0,0,0), ACCESS_P, (1, MAX_SEQUENCES), ASN_INTEGER, "patternSequenceNumber", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.4.8.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_SPLITS), ASN_INTEGER, "maxSplits", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.4.9.1.1.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "splitNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.9.1.2.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "splitPhase", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.9.1.3.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "splitTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.9.1.4.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_P, (2, 8), ASN_INTEGER, "splitMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.9.1.5.0' : [ (MAX_SPLITS,MAX_PHASES,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "splitCoordPhase", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.4.10.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "coordPatternStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.11.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "localFreeStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.12.0' : [ (0,0,0,0), ACCESS_RD, (0, 510), ASN_INTEGER, "coordCycleStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.13.0' : [ (0,0,0,0), ACCESS_RD, (0, 510), ASN_INTEGER, "coordSyncStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.4.14.0' : [ (0,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "systemPatternControl", "mandatory" ],  #| AF_BU
		'1.3.6.1.4.1.1206.4.2.1.4.15.0' : [ (0,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "systemSyncControl", "mandatory" ],  #| AF_BU
		'1.3.6.1.4.1.1206.4.2.1.4.16.0' : [ (0,0,0,0), ACCESS_RW, (1, 7), ASN_INTEGER, "unitCoordSyncPoint", "optional" ],
		
    # timebaseAsc - - NTCIP 1202		
		'1.3.6.1.4.1.1206.4.2.1.5.1.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "timebaseAscPatternSync", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.5.2.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_TBC_ACTIONS), ASN_INTEGER, "maxTimebaseAscActions", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.5.3.1.1.0' : [ (MAX_TBC_ACTIONS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "timebaseAscActionNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.5.3.1.2.0' : [ (MAX_TBC_ACTIONS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "timebaseAscPattern", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.5.3.1.3.0' : [ (MAX_TBC_ACTIONS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "timebaseAscAuxillaryFunction", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.5.3.1.4.0' : [ (MAX_TBC_ACTIONS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "timebaseAscSpecialFunction", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.5.4.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "timebaseAscActionStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.5.5.0' : [ (0,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "actionPlanControl", "optional" ], # | AF_BU
		
    # preempt - - NTCIP 1202		
		'1.3.6.1.4.1.1206.4.2.1.6.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_PREEMPTS), ASN_INTEGER, "maxPreempts", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.1.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "preemptNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.2.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, 63), ASN_INTEGER, "preemptControl", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.3.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, MAX_PREEMPTS), ASN_INTEGER, "preemptLink", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.4.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, 600), ASN_INTEGER, "preemptDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.5.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "preemptMinimumDuration", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.6.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "preemptMinimumGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.7.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "preemptMinimumWalk", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.8.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "preemptEnterPedClear", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.9.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "preemptTrackGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.10.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "preemptDwellGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.11.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "preemptMaximumPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.12.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_PHASES), ASN_OCTET_STR, "preemptTrackPhase", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.13.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_PHASES), ASN_OCTET_STR, "preemptDwellPhase", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.14.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_PHASES), ASN_OCTET_STR, "preemptDwellPed", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.15.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_PHASES), ASN_OCTET_STR, "preemptExitPhase", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.16.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_RD, (1, 10), ASN_INTEGER, "preemptState", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.17.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_VEH_OVERLAPS), ASN_OCTET_STR, "preemptTrackOverlap", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.18.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_VEH_OVERLAPS), ASN_OCTET_STR, "preemptDwellOverlap", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.19.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_PHASES), ASN_OCTET_STR, "preemptCyclingPhase", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.20.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_PHASES), ASN_OCTET_STR, "preemptCyclingPed", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.21.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P2, (0, MAX_VEH_OVERLAPS), ASN_OCTET_STR, "preemptCyclingOverlap", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.22.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "preemptEnterYellowChange", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.23.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "preemptEnterRedClear", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.24.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "preemptTrackYellowChange", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.25.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "preemptTrackRedClear", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.26.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (1, MAX_SEQUENCES), ASN_INTEGER, "preemptSequenceNumber", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.6.2.1.27.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "preemptExitType", "optional" ],
		
		'1.3.6.1.4.1.1206.4.2.1.6.3.1.1.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "preemptControlNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.6.3.1.2.0' : [ (MAX_PREEMPTS,0,0,0), ACCESS_RW, (0, 1), ASN_INTEGER, "preemptControlState", "mandatory" ], # | AF_BU
		
		'1.3.6.1.4.1.1206.4.2.1.6.4.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_PREEMPTS), ASN_INTEGER, "preemptStatus", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.6.5.0' : [ (0,0,0,0), ACCESS_RD, (0, MAX_PREEMPT_GROUPS), ASN_INTEGER, "maxPreemptGroups", "optional" ],
		
		'1.3.6.1.4.1.1206.4.2.1.6.6.1.1.0' : [ (MAX_PREEMPT_GROUPS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "preemptStatusGroupNumber", "optional" ],
		'1.3.6.1.4.1.1206.4.2.1.6.6.1.2.0' : [ (MAX_PREEMPT_GROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "preemptStatusGroup", "optional" ],
		
    # ring - - NTCIP 1202		
		'1.3.6.1.4.1.1206.4.2.1.7.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_RINGS), ASN_INTEGER, "maxRings", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.7.2.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_SEQUENCES), ASN_INTEGER, "maxSequences", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.7.3.1.1.0' : [ (MAX_SEQUENCES,MAX_RINGS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "sequenceNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.7.3.1.2.0' : [ (MAX_SEQUENCES,MAX_RINGS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "sequenceRingNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.7.3.1.3.0' : [ (MAX_SEQUENCES,MAX_RINGS,0,0), ACCESS_P2, (0, RING_SEQUENCE_SIZE), ASN_OCTET_STR, "sequenceData", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.7.4.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_RINGGROUPS), ASN_INTEGER, "maxRingControlGroups", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.7.5.1.1.0' : [ (MAX_RINGGROUPS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "ringControlGroupNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.7.5.1.2.0' : [ (MAX_RINGGROUPS,0,0,0), ACCESS_RW, (1, (1 << MAX_RINGS) - 1), ASN_INTEGER, "ringControlGroupStopTime", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.4.2.1.7.5.1.3.0' : [ (MAX_RINGGROUPS,0,0,0), ACCESS_RW, (1, (1 << MAX_RINGS) - 1), ASN_INTEGER, "ringControlGroupForceOff", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.4.2.1.7.5.1.4.0' : [ (MAX_RINGGROUPS,0,0,0), ACCESS_RW, (1, (1 << MAX_RINGS) - 1), ASN_INTEGER, "ringControlGroupMax2", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.4.2.1.7.5.1.5.0' : [ (MAX_RINGGROUPS,0,0,0), ACCESS_RW, (1, (1 << MAX_RINGS) - 1), ASN_INTEGER, "ringControlGroupMaxInhibit", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.4.2.1.7.5.1.6.0' : [ (MAX_RINGGROUPS,0,0,0), ACCESS_RW, (1, (1 << MAX_RINGS) - 1), ASN_INTEGER, "ringControlGroupPedRecycle", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.4.2.1.7.5.1.7.0' : [ (MAX_RINGGROUPS,0,0,0), ACCESS_RW, (1, (1 << MAX_RINGS) - 1), ASN_INTEGER, "ringControlGroupRedRest", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.4.2.1.7.5.1.8.0' : [ (MAX_RINGGROUPS,0,0,0), ACCESS_RW, (1, (1 << MAX_RINGS) - 1), ASN_INTEGER, "ringControlGroupOmitRedClear", "mandatory" ], # | AF_BU
		'1.3.6.1.4.1.1206.4.2.1.7.5.1.9.0' : [ (MAX_RINGGROUPS,0,0,0), ACCESS_RW, (1, (1 << MAX_RINGS) - 1), ASN_INTEGER, "ringControlGroupMax3", "mandatory" ], # | AF_BU
		
		'1.3.6.1.4.1.1206.4.2.1.7.6.1.1.0' : [ (MAX_RINGS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "ringStatus", "mandatory" ],
		
    # channel -- NTCIP 1202		
		'1.3.6.1.4.1.1206.4.2.1.8.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_CHANNELS), ASN_INTEGER, "maxChannels", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.8.2.1.1.0' : [ (MAX_CHANNELS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "channelNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.8.2.1.2.0' : [ (MAX_CHANNELS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "channelControlSource", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.8.2.1.3.0' : [ (MAX_CHANNELS,0,0,0), ACCESS_P, (2, 5), ASN_INTEGER, "channelControlType", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.8.2.1.4.0' : [ (MAX_CHANNELS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "channelFlash", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.8.2.1.5.0' : [ (MAX_CHANNELS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "channelDim", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.8.3.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_CHANGROUPS), ASN_INTEGER, "maxChannelStatusGroups", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.8.4.1.1.0' : [ (MAX_CHANGROUPS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "channelStatusGroupNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.8.4.1.2.0' : [ (MAX_CHANGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "channelStatusGroupReds", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.8.4.1.3.0' : [ (MAX_CHANGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "channelStatusGroupYellows", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.8.4.1.4.0' : [ (MAX_CHANGROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "channelStatusGroupGreens", "mandatory" ],
		
    # overlap - - NTCIP 1202		
		'1.3.6.1.4.1.1206.4.2.1.9.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_VEH_OVERLAPS), ASN_INTEGER, "maxOverlaps", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.9.2.1.1.0' : [ (MAX_VEH_OVERLAPS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "overlapNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.9.2.1.2.0' : [ (MAX_VEH_OVERLAPS,0,0,0), ACCESS_P2, (2, 6), ASN_INTEGER, "overlapType", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.9.2.1.3.0' : [ (MAX_VEH_OVERLAPS,0,0,0), ACCESS_P2, (0, MAX_PHASES), ASN_OCTET_STR, "overlapIncludedPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.9.2.1.4.0' : [ (MAX_VEH_OVERLAPS,0,0,0), ACCESS_P2, (0, MAX_PHASES), ASN_OCTET_STR, "overlapModifierPhases", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.9.2.1.5.0' : [ (MAX_VEH_OVERLAPS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "overlapTrailGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.9.2.1.6.0' : [ (MAX_VEH_OVERLAPS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "overlapTrailYellow", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.9.2.1.7.0' : [ (MAX_VEH_OVERLAPS,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "overlapTrailRed", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.9.3.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_OVERLAP_GROUPS), ASN_INTEGER, "maxOverlapStatusGroups", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.9.4.1.1.0' : [ (MAX_OVERLAP_GROUPS,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "overlapStatusGroupNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.9.4.1.2.0' : [ (MAX_OVERLAP_GROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "overlapStatusGroupReds", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.9.4.1.3.0' : [ (MAX_OVERLAP_GROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "overlapStatusGroupYellows", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.9.4.1.4.0' : [ (MAX_OVERLAP_GROUPS,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "overlapStatusGroupGreens", "mandatory" ],
		
    # ts2port1 - NTCIP 1202		
		'1.3.6.1.4.1.1206.4.2.1.10.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_PORT1_DEVICES), ASN_INTEGER, "maxPort1Addresses", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.1.10.2.1.1.0' : [ (MAX_PORT1_DEVICES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "port1Number", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.10.2.1.2.0' : [ (MAX_PORT1_DEVICES,0,0,0), ACCESS_P, (0, 2), ASN_INTEGER, "port1DevicePresent", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.10.2.1.3.0' : [ (MAX_PORT1_DEVICES,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "port1Frame40Enable", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.10.2.1.4.0' : [ (MAX_PORT1_DEVICES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "port1Status", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.10.2.1.5.0' : [ (MAX_PORT1_DEVICES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "port1FaultFrame", "mandatory" ],
		
    # ascBlock - NTCIP 1202		
		'1.3.6.1.4.1.1206.4.2.1.11.1.0' : [ (0,0,0,0), ACCESS_RW, (2, SIZE_ASCBLKGETCTRL), ASN_OCTET_STR, "ascBlockGetControl", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.11.2.0' : [ (0,0,0,0), ACCESS_RW, (2, SIZE_ASCBLOCKDATA), ASN_OCTET_STR, "ascBlockData", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.1.11.3.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "ascBlockErrorStatus", "mandatory" ],
		
    # *********************************************************************RAMPMETER*********************************************************************************************************		
    # RMC GENERAL CONFIGURATION NODE - NTCIP 1207		
		'1.3.6.1.4.1.1206.4.2.2.1.1.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcCommRefreshThreshold", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.1.2.0' : [ (0,0,0,0), ACCESS_P, (1, INT8U_MAX), ASN_INTEGER, "rmcCalcInterval", "mandatory" ],
		
    # MAINLINE LANE CONFIGURATION		
		'1.3.6.1.4.1.1206.4.2.2.2.1.0' : [ (0,0,0,0), ACCESS_P, (1, INT8U_MAX), ASN_INTEGER, "rmcAveragingPeriods", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.2.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_MAINLINE_LANES), ASN_INTEGER, "rmcMaxNumML", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.3.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_MAINLINE_LANES), ASN_INTEGER, "rmcNumML", "mandatory" ],
		
    # Mainline Lane Configuration and Control Table - NTCIP 1207		
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.1.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMLNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.2.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (1, 5), ASN_INTEGER, "rmcMLMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.3.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMLLeadZoneLength", "deprecated" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.4.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMLTrailZoneLength", "deprecated" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.5.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (1, 9), ASN_INTEGER, "rmcMLUsageMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.6.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcSpeedTrapSpacing", "deprecated" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.7.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMLErraticCount", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.8.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcMLMaxPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.9.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcMLNoActivity", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.10.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcVehicleLength", "deprecated" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.11.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcMLLeadZoneLengthV2", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.12.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcMLTrailZoneLengthV2", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.13.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcSpeedTrapSpacingV2", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.4.1.14.0' : [ (MAX_MAINLINE_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcVehicleLengthV2", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.2.2.5.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcAverageFlowRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.6.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcAverageOccupancy", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.7.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "rmcAverageSpeed", "mandatory" ],
		
    # Mainline Lane Status Table - NTCIP 1207		
		'1.3.6.1.4.1.1206.4.2.2.2.8.1.1.0' : [ (0,0,0,0), ACCESS_RD, (1, 8), ASN_INTEGER, "rmcMLLeadStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.8.1.2.0' : [ (0,0,0,0), ACCESS_RD, (1, 8), ASN_INTEGER, "rmcMLTrailStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.8.1.3.0' : [ (0,0,0,0), ACCESS_RD, (1, 4), ASN_INTEGER, "rmcMLStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.8.1.4.0' : [ (0,0,0,0), ACCESS_RD, (1, 8), ASN_INTEGER, "rmcMLUsageStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.8.1.5.0' : [ (0,0,0,0), ACCESS_RD, (1, INT16U_MAX), ASN_INTEGER, "rmcMLHistLeadStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.8.1.6.0' : [ (0,0,0,0), ACCESS_RD, (1, INT16U_MAX), ASN_INTEGER, "rmcMLHistTrailStatus", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.2.2.9.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMaxNumFlowNoActivityTableEntries", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.10.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcNumFlowNoActivityTableEntries", "mandatory" ],
		
    # Flow Based No Activity Table -- NTCIP 1207		
		'1.3.6.1.4.1.1206.4.2.2.2.11.1.1.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMLFlowBasedNoActivityIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.11.1.2.0' : [ (0,0,0,0), ACCESS_RD, (1, INT16U_MAX), ASN_INTEGER, "rmcFlowBasedNoActivityThreshold", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.11.1.3.0' : [ (0,0,0,0), ACCESS_RD, (1, INT16U_MAX), ASN_INTEGER, "rmcFlowBasedNoActivityInterval", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.2.2.12.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "rmcNumFlowRateLanes", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.13.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "rmcNumAverageOccupancyLanes", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.14.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "rmcNumAverageSpeedLanes", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.2.15.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "rmcFlowBasedNoActivityDuration", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.2.3.1.1.0' : [ (0,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_UNSIGNED, "rmcMaxNumMeteredLanes", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.2.0' : [ (0,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_UNSIGNED, "rmcNumMeteredLanes", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.2.3.6.0' : [ (0,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_UNSIGNED, "rmcHistDetectorReset", "mandatory" ],
		
    # Metered Lane Configuration Table - NTCIP 1207		
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.1.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMeterNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.2.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (1, INT8U_MAX), ASN_INTEGER, "rmcDependGroupNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.3.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (1, INT8U_MAX), ASN_INTEGER, "rmcDependGroupSeqNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.4.0' : [ (0,0,0,0), ACCESS_P, (1, 6), ASN_INTEGER, "rmcCmdSourcePriorityOrder", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.5.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcDemandErraticCount", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.6.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcDemandMaxPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.7.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcDemandNoActivity", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.8.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMinMeterTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.9.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMinNonMeterTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.10.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcAbsoluteMinMeterRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.11.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcAbsoluteMaxMeterRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.12.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcSystemMinMeterRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.13.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcSystemMaxMeterRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.14.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcStartAlert", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.15.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcStartWarning", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.16.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcStartGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.17.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcStartGapTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.18.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcStartGapQueueDetectorNum", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.19.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcStartYellow", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.20.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcStartRed", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.21.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMinRed", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.22.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcRedViolationClearance", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.23.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcRedViolationAdjust", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.24.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMinGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.25.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMaxGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.26.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcYellow", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.27.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcShortStopTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.28.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcShortStopOccupancy", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.29.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcShortStopQueueDetectorNum", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.30.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcLongStopTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.31.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcDemandGap", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.32.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcDemandRed", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.33.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcShutNormalRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.34.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcShutWarning", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.35.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcShutTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.36.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcPostMeterGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.37.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "rmcQueueViolationFlag", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.38.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "rmcQueueShutdownFlag", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.39.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "rmcQueueAdjustUsage", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.40.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcDemandDependMaxPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.3.1.41.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcDemandDependNoActivity", "mandatory" ],
		
    # Metered Lane Control Table -- Begin		
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.1.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "rmcMeterMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.2.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (1, 6), ASN_INTEGER, "rmcManualAction", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.3.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcManualPlan", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.4.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcManualRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.5.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcManualVehiclesPerGrn", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.6.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (1, 6), ASN_INTEGER, "rmcIntercoAction", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.7.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcIntercoPlan", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.8.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcInterconRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.9.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcIntercoVehiclesPMAX_METERING_LANESrGrn", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.10.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (1, 6), ASN_INTEGER, "rmcCommActionMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.11.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcCommPlan", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.12.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcCommRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.13.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcCommVehiclesPerGrn", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.14.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (1, 5), ASN_INTEGER, "rmcDefaultAction", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.15.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcDefaultPlan", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.16.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcDefaultRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.17.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcDefaultVehiclesPerGrn", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.18.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "rmcDemandMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.19.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, 3), ASN_INTEGER, "rmcPreMeterNonGreen", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.20.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcCritFlowRateThresh", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.21.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcCritOccupancyThresh", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.7.1.22.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcCriticalSpeedTreshold", "mandatory" ],
		
    # Metered Lane Status Table -- Begin		
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.1.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, 5), ASN_INTEGER, "rmcRequestedCommandSource", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.2.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, 5), ASN_INTEGER, "rmcImplementCommandSource", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.3.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, 8), ASN_INTEGER, "rmcImplementAction", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.4.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "rmcImplementPlan", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.5.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcImplementRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.6.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "rmcImplementVehiclesPerGrn", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.7.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, 5), ASN_INTEGER, "rmcRequestAction", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.8.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "rmcRequestPlan", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.9.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcRequestRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.10.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "rmcRequestVehiclesPerGrn", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.11.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, 7), ASN_INTEGER, "rmcCommAction", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.12.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcBaseMeterRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.13.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcActiveMeterRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.14.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, 6), ASN_INTEGER, "rmcTBActionStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.15.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "rmcTBPlanStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.16.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcTBRateStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.17.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "rmcTBVehiclesPerGrnStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.18.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, 0), ASN_INTEGER, "rmcActiveInterval", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.19.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcTBCMinMeterRateStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.20.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcTBCMaxMeterRateStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.21.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcOperMinMeterRateStatus", "deprecated" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.22.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcOperMaxMeterRateStatus", "deprecated" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.23.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, 9), ASN_INTEGER, "rmcDemandStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.24.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcHistDemandStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.25.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "rmcCycleCount", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.26.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcTBCMinMeterRateStatusV2", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.27.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcTBCMaxMeterRateStatusV2", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.28.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, 3), ASN_INTEGER, "rmcCumulQueAdjStat", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.1.8.1.29.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, 1), ASN_INTEGER, "rmcMainQueueFlag", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.2.3.2.1.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMaxNumDependGroups", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.2.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcNumDependGroups", "mandatory" ],
		
    # Dependency Group Configuration and Control Table -- Begin		
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.1.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "rmcDependGroupMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.2.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "rmcSignalServiceMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.3.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcShutGapTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.4.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcShutGapReductTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.5.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcShutGapReductValue", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.6.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcGreenOffset", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.7.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMinFractionalOffset", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.8.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcPriorityLaneNum", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.9.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcPriorityLaneRedDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.10.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "rmcMergeMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.11.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMergeGap", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.12.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMergeDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.13.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "rmcQueueMergeFlag", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.14.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMergeErraticCount", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.15.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcMergeMaxPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.16.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcMergeNoActivity", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.3.1.17.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMinMutexRed", "mandatory" ],
		
    # Dependency Group Status Table - Begin		
		'1.3.6.1.4.1.1206.4.2.2.3.2.4.1.1.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, 1), ASN_INTEGER, "rmcMergeFlag", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.4.1.2.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, 7), ASN_INTEGER, "rmcMergeStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.4.1.3.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "rmcHistMergeStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.2.4.1.4.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, 1), ASN_INTEGER, "rmcMergeOverStat", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.2.3.3.1.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMaxNumQueueEntries", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.2.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcNumQueueEntries", "mandatory" ],
		
    # Queue Detector Configuration and Control Table -- Begin		
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.1.0' : [ (MAX_QUEUES,0,0,0), ACCESS_RD, (1, MAX_QUEUES), ASN_INTEGER, "rmcQueueNum", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.2.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (1, 3), ASN_INTEGER, "rmcQueueType", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.3.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "rmcQueueDetectMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.4.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcQueueLengthUpLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.5.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcQueueLengthLoLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.6.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcQueueOccUpLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.7.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcQueueOccUpDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.8.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcQueueOccLoLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.9.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcQueueOccLoDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.10.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcQueueQOccUpLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.11.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcQueueQOccUpDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.12.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcQueueQOccLoLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.13.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcQueueQOccLowDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.14.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (1, 4), ASN_INTEGER, "rmcQueueAdjustMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.15.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcQueueAdjustRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.16.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcQueueAdjustRateLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.17.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcQueueAdjustRateDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.18.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcQueueAdjustRate Iter", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.19.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcQueueAdjustLevel", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.20.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcQueueAdjustLevelLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.21.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcQueueAdjustLevelDelay", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.22.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcQueueAdjustLevelIter", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.23.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcQueueReplaceRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.24.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcQueueDetectorErraticCount", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.25.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcQueueMaxPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.26.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcQueueNoActivity", "mandatory" ],
		# ADDED in V2
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.27.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcQueueDependMaxPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.1.28.0' : [ (MAX_QUEUES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcQueueDependNoActivity", "mandatory" ],
		
    # Queue Detector Status Table -- Begin		
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.10.1.1.0' : [ (MAX_QUEUES,0,0,0), ACCESS_RD, (0, 1), ASN_INTEGER,"rmcQueueFlag", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.10.1.2.0' : [ (MAX_QUEUES,0,0,0), ACCESS_RD, (1, 9), ASN_INTEGER,"rmcQueueStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.3.3.10.1.3.0' : [ (MAX_QUEUES,0,0,0), ACCESS_RD, (1, INT16U_MAX), ASN_INTEGER,"rmcHistQueueStatus", "mandatory" ],
		
    # Passage Detector Configuration and Control Table -- Begin		
		'1.3.6.1.4.1.1206.4.2.2.3.5.1.1.1.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcPassageMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.5.1.1.2.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcPassageErraticCount", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.5.1.1.3.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcPassageMaxPresence", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.5.1.1.4.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcPassageNoActivity", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.5.1.1.5.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcPassageDependNoActivity", "mandatory" ],
		
    # Passage Detector Status Table -- Begin		
		'1.3.6.1.4.1.1206.4.2.2.3.5.2.1.1.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, 8), ASN_INTEGER, "rmcPassageStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.5.2.1.2.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, INT16U_MAX), ASN_INTEGER, "rmcHistPassageStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.5.2.1.3.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcPassageVehicleCount", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.3.5.2.1.4.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcRedViolationCount", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.2.4.1.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMaxNumMeteringPlans", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.4.2.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcNumMeteringPlans", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.4.3.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMaxNumLevelsPerPlan", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.4.4.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcNumMeteringLevels", "deprecated" ],
		
    # Metering Plan Table - Begin		
		'1.3.6.1.4.1.1206.4.2.2.4.5.1.1.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMeteringPlanNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.4.5.1.2.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMeteringLevel", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.4.5.1.3.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcMeteringRate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.4.5.1.4.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcFlowRateThreshold", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.4.5.1.5.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcOccupancyThreshold", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.4.5.1.6.0' : [ (MAX_METERING_LANES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcSpeedThreshold", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.2.5.1.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMaxNumTBCActions", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.2.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcNumTBCActions", "mandatory" ],
		
    # Timebase Control Action Table -- Begin		
		'1.3.6.1.4.1.1206.4.2.2.5.3.1.1.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcActionNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.3.1.2.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "rmcActionMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.3.1.3.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMeterActionNum", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.3.1.4.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMLActionNum", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.2.5.4.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMaxNumMeterTBCActions", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.5.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMeterTBCActions", "mandatory" ],
		
    # Metered Lane Timebase Control Action Table -- Begin		
		'1.3.6.1.4.1.1206.4.2.2.5.6.1.1.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMeterActionIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.6.1.2.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "rmcMeterActionMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.6.1.3.0' : [ (0,0,0,0), ACCESS_P, (1, 6), ASN_INTEGER, "rmcTBActionCtrl", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.6.1.4.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcTBPlanCtrl", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.6.1.5.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcTB Rate Ctrl", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.6.1.6.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcTBVehiclesPerGrnCtrl", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.6.1.7.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcTBCMinMeterRateCtrl", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.6.1.8.0' : [ (0,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "rmcTBCMaxMeterRateCtrl", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.2.5.7.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMaxNumMLTBCActions", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.8.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcNumMLTBCActions", "mandatory" ],
		
    # Mainline Timebase Control Action Table - Begin		
		'1.3.6.1.4.1.1206.4.2.2.5.9.1.1.0' : [ (0,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "rmcMLActionIndex", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.9.1.2.0' : [ (0,0,0,0), ACCESS_P, (0, 1), ASN_INTEGER, "rmcMLActionMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.5.9.1.3.0' : [ (0,0,0,0), ACCESS_P, (1, 8), ASN_INTEGER, "rmcTBMLUsageMode", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.2.6.1.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcAdvSignOutNumber", "mandatory" ],
		
    # Mainline Lane Physical Input Table - Begin		
		'1.3.6.1.4.1.1206.4.2.2.6.2.1.1.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMLLeadInNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.6.2.1.2.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMLTrailInNumber", "mandatory" ],
		
    # Queue Detector Physical Input Table - Begin		
		'1.3.6.1.4.1.1206.4.2.2.6.3.1.1.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMetQueueInNumber", "mandatory" ],
		
    # Metered Lane Physical Input/Output Table - Begin		
		'1.3.6.1.4.1.1206.4.2.2.6.4.1.1.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMeterDemandInNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.6.4.1.2.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMeterPassageInNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.6.4.1.3.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMeterRedOutNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.6.4.1.4.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMeterYellowOutNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.6.4.1.5.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcMeterGreenOutNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.6.4.1.6.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcAdvSignOutNumber", "mandatory" ],
		
    # Dependency Group Physical Input/Output Table - Begin		
		'1.3.6.1.4.1.1206.4.2.2.6.5.1.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcDependMergeInNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.2.6.5.2.0' : [ (0,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "rmcDependAdvSignOutNumber", "mandatory" ],
		
    # *********************************************************************RAMPMETER ENDS************************************************************************************************		
		
    # globalConfiguration - NTCIP 1201		
		'1.3.6.1.4.1.1206.4.2.6.1.1.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "globalSetIDParameter", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.1.2.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_GLOBALMODULES), ASN_INTEGER, "globalMaxModules", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.1.3.1.1.0' : [ (MAX_GLOBALMODULES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "moduleNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.1.3.1.2.0' : [ (MAX_GLOBALMODULES,0,0,0), ACCESS_RD, (0, SIZE_GLOBALMOD_STR), ASN_OCTET_STR, "moduleDeviceNode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.1.3.1.3.0' : [ (MAX_GLOBALMODULES,0,0,0), ACCESS_RD, (0, SIZE_GLOBALMOD_STR), ASN_OCTET_STR, "moduleMake", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.1.3.1.4.0' : [ (MAX_GLOBALMODULES,0,0,0), ACCESS_RD, (0, SIZE_GLOBALMOD_STR), ASN_OCTET_STR, "moduleModel", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.1.3.1.5.0' : [ (MAX_GLOBALMODULES,0,0,0), ACCESS_RD, (0, SIZE_GLOBALMOD_STR), ASN_OCTET_STR, "moduleVersion", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.1.3.1.6.0' : [ (MAX_GLOBALMODULES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "moduleType", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.1.4.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX + 1), ASN_OCTET_STR, "controllerBaseStandards", "mandatory" ],
		
    # globalDBManagement - NTCIP 1201		
		'1.3.6.1.4.1.1206.4.2.6.2.1.0' : [ (0,0,0,0), ACCESS_RW, (0, INT8U_MAX), ASN_INTEGER, "dbCreateTransaction", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.2.6.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "dbVerifyStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.2.7.0' : [ (0,0,0,0), ACCESS_RD, (0, 200), ASN_OCTET_STR, "dbVerifyError", "mandatory" ],
		
    # globalTimeManagement - NTCIP 1201		
		'1.3.6.1.4.1.1206.4.2.6.3.1.0' : [ (0,0,0,0), ACCESS_RW, (0, INT32U_MAX), ASN_COUNTER, "globalTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.2.0' : [ (0,0,0,0), ACCESS_P, (1, MAX_DST_VALUE), ASN_INTEGER, "globalDaylightSaving", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.3.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_TBC_SCHEDULES), ASN_INTEGER, "maxTimeBaseScheduleEntries", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.3.3.2.1.1.0' : [ (MAX_TBC_SCHEDULES,0,0,0), ACCESS_RD, (1, INT16U_MAX), ASN_INTEGER, "timeBaseScheduleNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.3.2.1.2.0' : [ (MAX_TBC_SCHEDULES,0,0,0), ACCESS_P, (0, INT16U_MAX), ASN_INTEGER, "timeBaseScheduleMonth", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.3.2.1.3.0' : [ (MAX_TBC_SCHEDULES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "timeBaseScheduleDay", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.3.2.1.4.0' : [ (MAX_TBC_SCHEDULES,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_UNSIGNED, "timeBaseScheduleDate", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.3.2.1.5.0' : [ (MAX_TBC_SCHEDULES,0,0,0), ACCESS_P, (0, MAX_TBC_DAYPLANS), ASN_INTEGER, "timeBaseScheduleDayPlan", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.3.3.3.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_TBC_DAYPLANS), ASN_INTEGER, "maxDayPlans", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.3.4.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_TBC_EVENTS), ASN_INTEGER, "maxDayPlanEvents", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.3.3.5.1.1.0' : [ (MAX_TBC_DAYPLANS,MAX_TBC_EVENTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "dayPlanNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.3.5.1.2.0' : [ (MAX_TBC_DAYPLANS,MAX_TBC_EVENTS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "dayPlanEventNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.3.5.1.3.0' : [ (MAX_TBC_DAYPLANS,MAX_TBC_EVENTS,0,0), ACCESS_P, (0, 23), ASN_INTEGER, "dayPlanHour", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.3.5.1.4.0' : [ (MAX_TBC_DAYPLANS,MAX_TBC_EVENTS,0,0), ACCESS_P, (0, 59), ASN_INTEGER, "dayPlanMinute", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.3.5.1.5.0' : [ (MAX_TBC_DAYPLANS,MAX_TBC_EVENTS,0,0), ACCESS_P, (0, SIZE_ACTIONOID), ASN_OBJECT_ID, "dayPlanActionNumberOID", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.3.3.6.0' : [ (0,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "dayPlanStatus", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.3.7.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "timeBaseScheduleTableStatus", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.3.4.0' : [ (0,0,0,0), ACCESS_P, (MIN_TZ_OFFSET, MAX_TZ_OFFSET), ASN_INTEGER, "globalLocalTimeDifferential", "deprecated" ],
		'1.3.6.1.4.1.1206.4.2.6.3.5.0' : [ (0,0,0,0), ACCESS_P, (MIN_TZ_OFFSET, MAX_TZ_OFFSET), ASN_INTEGER, "controllerStandardTimeZone", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.6.0' : [ (0,0,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "controllerLocalTime", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.3.7.1.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_DST_ENTRIES), ASN_INTEGER, "maxDaylightSavingEntries", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.3.7.2.1.1.0' : [ (MAX_DST_ENTRIES,0,0,0), ACCESS_RD, (1, MAX_DST_ENTRIES), ASN_INTEGER, "dstEntryNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.7.2.1.2.0' : [ (MAX_DST_ENTRIES,0,0,0), ACCESS_P, (DST_OCCURRENCES_FIRST, DST_OCCURRENCES_SPECIFIC_DAY_OF_MONTH), ASN_INTEGER, "dstBeginMonth", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.7.2.1.3.0' : [ (MAX_DST_ENTRIES,0,0,0), ACCESS_P, (DST_OCCURRENCES_FIRST, DST_OCCURRENCES_SPECIFIC_DAY_OF_MONTH), ASN_INTEGER, "dstBeginOccurrences", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.7.2.1.4.0' : [ (MAX_DST_ENTRIES,0,0,0), ACCESS_P, (SUNDAY, SATURDAY), ASN_INTEGER, "dstBeginDayOfWeek", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.7.2.1.5.0' : [ (MAX_DST_ENTRIES,0,0,0), ACCESS_P, (1, 31), ASN_INTEGER, "dstBeginDayOfMonth", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.7.2.1.6.0' : [ (MAX_DST_ENTRIES,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_UNSIGNED, "dstBeginSecondsToTransition", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.7.2.1.7.0' : [ (MAX_DST_ENTRIES,0,0,0), ACCESS_P, (DST_MONTH_JAN, DST_MONTH_DEC), ASN_INTEGER, "dstEndMonth", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.7.2.1.8.0' : [ (MAX_DST_ENTRIES,0,0,0), ACCESS_P, (DST_OCCURRENCES_FIRST, DST_OCCURRENCES_SPECIFIC_DAY_OF_MONTH), ASN_INTEGER, "dstEndOccurrences", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.7.2.1.9.0' : [ (MAX_DST_ENTRIES,0,0,0), ACCESS_P, (SUNDAY, SATURDAY), ASN_INTEGER, "dstEndDayOfWeek", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.7.2.1.10.0' : [ (MAX_DST_ENTRIES,0,0,0), ACCESS_P, (1, 31), ASN_INTEGER, "dstEndDayOfMonth", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.7.2.1.11.0' : [ (MAX_DST_ENTRIES,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_UNSIGNED, "dstEndSecondsToTransition", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.3.7.2.1.12.0' : [ (MAX_DST_ENTRIES,0,0,0), ACCESS_P, (0, MAX_DST_SECONDS), ASN_INTEGER, "dstSecondsToAdjust", "mandatory" ],
		
    # globalReport - NTCIP 1103		
		'1.3.6.1.4.1.1206.4.2.6.4.1.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_EVENTLOGCONFIGS), ASN_INTEGER, "maxEventLogConfigs", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.4.2.1.1.0' : [ (NUM_EVENTLOGCONFIGS,0,0,0), ACCESS_RD, (1, INT16U_MAX), ASN_INTEGER, "eventConfigID", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.2.1.2.0' : [ (NUM_EVENTLOGCONFIGS,0,0,0), ACCESS_P, (1, INT8U_MAX), ASN_INTEGER, "eventConfigClass", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.2.1.3.0' : [ (NUM_EVENTLOGCONFIGS,0,0,0), ACCESS_P, (EVENTMODEOTHER, EVENTMODEANDEDWITHVALUE), ASN_INTEGER, "eventConfigMode", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.2.1.4.0' : [ (NUM_EVENTLOGCONFIGS,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_UNSIGNED, "eventConfigCompareValue", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.2.1.5.0' : [ (NUM_EVENTLOGCONFIGS,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_UNSIGNED, "eventConfigCompareValue2", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.2.1.6.0' : [ (NUM_EVENTLOGCONFIGS,0,0,0), ACCESS_P, (0, SIZE_EVTCFGCOMPOID), ASN_OBJECT_ID, "eventConfigCompareOID", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.2.1.7.0' : [ (NUM_EVENTLOGCONFIGS,0,0,0), ACCESS_P, (0, SIZE_EVTCFGLOGOID), ASN_OBJECT_ID, "eventConfigLogOID", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.2.1.8.0' : [ (NUM_EVENTLOGCONFIGS,0,0,0), ACCESS_P, (EVENTACTIONOTHER, EVENTACTIONLOG), ASN_INTEGER, "eventConfigAction", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.2.1.9.0' : [ (NUM_EVENTLOGCONFIGS,0,0,0), ACCESS_RD, (EVENTACTIONOTHER, EVENTSTATUSERROR), ASN_INTEGER, "eventConfigStatus", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.4.3.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_EVENTLOGS), ASN_INTEGER, "maxEventLogSize", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.4.4.1.1.0' : [ (8,NUM_EVENTLOGS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "eventLogClass", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.4.1.2.0' : [ (8,NUM_EVENTLOGS,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "eventLogNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.4.1.3.0' : [ (8,NUM_EVENTLOGS,0,0), ACCESS_RD, (1, INT16U_MAX), ASN_INTEGER, "eventLogID", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.4.1.4.0' : [ (8,NUM_EVENTLOGS,0,0), ACCESS_RD, (0, INT32U_MAX), ASN_COUNTER, "eventLogTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.4.1.5.0' : [ (8,NUM_EVENTLOGS,0,0), ACCESS_RD, (0, SIZE_EVENTLOGVALUE), OBJT_OPAQUE, "eventLogValue", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.4.5.0' : [ (0,0,0,0), ACCESS_RD, (1, NUM_EVENTCLASSES), ASN_INTEGER, "maxEventClasses", "mandatory" ],
		
		'1.3.6.1.4.1.1206.4.2.6.4.6.1.1.0' : [ (NUM_EVENTCLASSES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "eventClassNumber", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.6.1.2.0' : [ (NUM_EVENTCLASSES,0,0,0), ACCESS_P, (0, INT8U_MAX), ASN_INTEGER, "eventClassLimit", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.6.1.3.0' : [ (NUM_EVENTCLASSES,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_COUNTER, "eventClassClearTime", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.6.1.4.0' : [ (NUM_EVENTCLASSES,0,0,0), ACCESS_P, (0, SIZE_EVTCFGCOMPOID), ASN_OCTET_STR, "eventClassDescription", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.6.1.5.0' : [ (NUM_EVENTCLASSES,0,0,0), ACCESS_RD, (0, INT8U_MAX), ASN_INTEGER, "eventClassNumRowsInLog", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.6.1.6.0' : [ (NUM_EVENTCLASSES,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "eventClassNumEvents", "mandatory" ],
		'1.3.6.1.4.1.1206.4.2.6.4.7.0' : [ (0,0,0,0), ACCESS_RD, (0, INT16U_MAX), ASN_INTEGER, "numEvents", "mandatory" ],
		
    # security -  - NTCIP 1103		
		'1.3.6.1.4.1.1206.4.2.6.5.1.0' : [ (0,0,0,0), ACCESS_P, (8, 16), ASN_OCTET_STR, "communityNameAdmin", "mandatory" ],  # AF_COMTY
		'1.3.6.1.4.1.1206.4.2.6.5.2.0' : [ (0,0,0,0), ACCESS_RD, (1, MAX_COMMUNITYNAMES), ASN_INTEGER, "communityNamesMax", "mandatory" ], # AF_COMTY 
		
		'1.3.6.1.4.1.1206.4.2.6.5.3.1.1.0' : [ (MAX_COMMUNITYNAMES,0,0,0), ACCESS_RD, (1, INT8U_MAX), ASN_INTEGER, "communityNameIndex", "mandatory" ], # AF_COMTY 
		'1.3.6.1.4.1.1206.4.2.6.5.3.1.2.0' : [ (MAX_COMMUNITYNAMES,0,0,0), ACCESS_P, (6, 16), ASN_OCTET_STR, "communityNameUser", "mandatory" ], # AF_COMTY 
		'1.3.6.1.4.1.1206.4.2.6.5.3.1.3.0' : [ (MAX_COMMUNITYNAMES,0,0,0), ACCESS_P, (0, INT32U_MAX), ASN_GAUGE, "communityNameAccessMask", "mandatory" ], # AF_COMTY 

}
