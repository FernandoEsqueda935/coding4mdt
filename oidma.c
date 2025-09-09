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
