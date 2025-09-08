
/*************************************************************************************************/
/*  Name       : bGenericDeprecatedObject                                                        */
/*                                                                                               */
/*  Description: Function to be used as handler for all Deprecated OIDs. If a SET is requested   */
/*               it responds with the same data that just arrived. If a GET is requested         */
/*               it builds the response based on the deprecated OID type and its minimum value.  */
/*************************************************************************************************/
static BOOLEAN bGenericDeprecatedObject(TYPE_COMMS_MSG *ptMsg,                    //!< [inout] message structure holding received message
                                        INT8U **ptrResp,                          //!< [inout] response buffer
                                        INT16U *sizResp,                          //!< [inout] response buffer size
                                        BOOLEAN __attribute__((unused)) validate, //!< unused
                                        INT16U *errorCode)                        //!< [out] return error code
{
  *errorCode = SNMPERRORNOERROR; // expect no errors

  if (ptMsg->boIsWriteTheValue == TRUE) { // SET.
    vManageDeprecatedSetRequest(&ptMsg->ucReadPointer, ptrResp, sizResp, errorCode);
  } else { // GET.
    vManageDeprecatedGetRequest(ptrResp, sizResp, errorCode, &OID[ptMsg->usObjectRow]);
  }
  return *errorCode == SNMPERRORNOERROR; // Return True if no error is present.
} // bGenericDeprecatedObject()

/*************************************************************************************************/
/*  Name       : vManageDeprecatedGetRequest                                                     */
/*                                                                                               */
/*  Description: Function used in bGenericDeprecatedObject when an SNMP GET request arrives.     */
/*               Builds the response msg depending of the deprecated object OID type.            */
/*************************************************************************************************/
static void vManageDeprecatedGetRequest(INT8U **ptrResp, INT16U *sizResp, INT16U *errorCode, const TYPE_OIDTABLE *ptOIDRow)
{
  INT8U *pu8Cursor = NULL; // Used to travel through the response buffer.
  INT16U u16Length = 0;    // Keeps the length of the data to be sent.
  BOOLEAN bIsOctet = FALSE;

  pu8Cursor = *ptrResp;
  *pu8Cursor++ = u8MapTypeToTag(ptOIDRow->oidType); // Write Tag to pos 0; Point to length octet.
  *sizResp -= 1;
  u16Length = u8GetOIDSize(ptOIDRow, &bIsOctet);
  bAppendLength(u16Length, &pu8Cursor, sizResp, errorCode); // Write Length bytes

  if (bIsOctet == FALSE) { // If not an octet, use the min value.
    vPackMinValue(pu8Cursor, u16Length, ptOIDRow->oidMin);
  } else { // Otherwise, send 0-filled octet with min length.
    memset(pu8Cursor, 0, u16Length);
  }
  *sizResp -= u16Length;  // Update available space in the response buffer.
  pu8Cursor += u16Length; // Move the pointer to the end of the written bytes.

  *ptrResp = pu8Cursor;
} // vManageDeprecatedGetRequest()

/*************************************************************************************************/
/*  Name       : vPackMinValue                                                                   */
/*                                                                                               */
/*  Description: Used when a GET request arrives on a signed or unsigned integer deprecated OID. */
/*               Packs the oid min value into pu8Cursor which must point to where the data octets*/
/*               must start in the response buffer.                                              */
/*************************************************************************************************/
static void vPackMinValue(INT8U *pu8Cursor, INT16U u16Length, INT32S s32OIDMinValue)
{
  INT16U u16Index = 0;

  for (u16Index = 0; u16Index < u16Length; u16Index++, pu8Cursor++) {
    *pu8Cursor = (INT8U)(s32OIDMinValue >> ((u16Length - u16Index - 1) * BITS_PER_BYTE)) & 0xFF; // Pack min value
  }
} // vPackMinValue()

/*************************************************************************************************/
/*  Name       : vManageDeprecatedSetRequest                                                     */
/*                                                                                               */
/*  Description: Function used in bGenericDeprecatedObject when an SNMP SET request arrives.     */
/*               Decodes how many bytes compose the SNMP msg and copies them to the response     */
/*               buffer.                                                                         */
/*************************************************************************************************/
static void vManageDeprecatedSetRequest(INT8U **pu8ReadPointer, INT8U **ptrResp, INT16U *sizResp, INT16U *errorCode)
{
  INT8U *pu8Cursor = NULL;
  INT16U u16Length = 0;       // Keeps the value of the Length byte.
  INT16U u16LengthOctets = 0; // Keeps how many bytes are needed to represent a length

  pu8Cursor = *pu8ReadPointer; // Point to length octets.
  pu8Cursor++;
  u16LengthOctets = u16GetLengthBytes(pu8Cursor);        // Amount of bytes the length is represented with.
  bDecodeLengthValue(&pu8Cursor, &u16Length, errorCode); // Here ptMsg->ucReadPointer is incremented.

  memcpy(*ptrResp, *pu8ReadPointer, u16LengthOctets + u16Length + 1); // Copy all incoming data to the response buffer.

  *sizResp -= u16LengthOctets + u16Length + 1; // Update pointers to the end of the data.
  *ptrResp += u16LengthOctets + u16Length + 1;
  *pu8ReadPointer += u16LengthOctets + u16Length + 1;
}

/*************************************************************************************************/
/*  Name       : u8GetOIDSize                                                                    */
/*                                                                                               */
/*  Description: Based on an OID type, returns how many bytes are required to store the data for */
/*               that same OID.                                                                  */
/*************************************************************************************************/
static INT8U u8GetOIDSize(const TYPE_OIDTABLE *tOID, BOOLEAN *bIsOctet)
{
  *bIsOctet = FALSE;
  switch (tOID->oidType) {
    case OBJT_INT1:
    case OBJT_SIGN_INT1:
      return 1;

    case OBJT_INT2:
    case OBJT_SIGN_INT2:
      return 2;

    case OBJT_COUNTER:
    case OBJT_GAUGE:
    case OBJT_TIME_TICKS:
    case OBJT_INT4:
    case OBJT_SIGN_INT4:
    case OBJT_INT_UNRES:
      return 4;

    case OBJT_OCTET:
    case OBJT_IP_ADDR:
    case OBJT_DISPLAY_STR:
    case OBJT_PHYS_ADDR:
    case OBJT_OWNER_STR:
    case OBJT_OID:
    case OBJT_OPAQUE:
      *bIsOctet = TRUE;
      return tOID->oidMin; // return min size.

    case OBJT_NULL:
      return 0;

    default:
      vMcSysLog(LOG_ERR, "unknown type");
      return 0;
  }

  return 0;
} // u8GetOIDSize()

//*******************************************************************************
//! startup initialization of volatile ntcip variables
//!
//! @remarks     Non-volatile objects in shared memory are initialized by the atcexec
//!               from flash and CANNOT be initialized here.
//*******************************************************************************
void InitOIDData(void)
{
  CHAR acBuffer[SIZE_GLOBALMOD_STR];                                     // Image of the system description
  INT8U *pu8Str = (INT8U *)("\x2B\x06\x01\x04\x01\x89\x36\x03\x15\x02"); // 1.3.6.1.4.1.1206.3.21.2      iso.org.dod.internet.private.enterprises.nema.nemaPrivate.McCain.ATC // OID string for McCain ATC
  CHAR acVersionImage[SIZE_GLOBALMOD_STR - 15];                          // Image of the version
  int ii = 0;

  memset(acBuffer, 0, sizeof(acBuffer));
  memset(acVersionImage, 0, sizeof(acVersionImage));

  // ---- System parameters ---------------------------------------------------
  vGetNtStringFromInternalOctet(acVersionImage, SIZE_GLOBALMOD_STR - 15, psATCsys->moduleVersion[GLOBEMOD_OMNI]);
  snprintf((char *)acBuffer, SIZE_GLOBALMOD_STR, "McCain Omni eX %s", (char *)(acVersionImage));
  vSetOctetString(sysDescr, (INT8U *)acBuffer, strlen((char *)(acBuffer)));
  vSetOctetString(sysObjectID, pu8Str, strlen((char *)(pu8Str)));
  // sysContact
  // sysName
  // sysLocation
  // sysServices  // Sum of (layer-1)^2 for layers: 1=physical, 2=subnet, 3=Internet, 4=end-end, 7=application

  // ---- Global module table -------------------------------------------------
  // set in main of each module
  // xx add compile date?  __DATE__

  // xxx fail safe here for community names if none set?

  // ---- Database transactions -------------------------------------------------
  psATCsys->tDbTransaction.u8DbCreateTransaction = DBTRANS_NORMAL;
  psATCsys->tDbTransaction.u8DbVerifyStatus = DBVERIFY_DONE_NOERROR;
  psATCsys->tDbTransaction.u8DbVerifyError[0] = 0;
  psATCsys->tDbTransaction.u8DbVerifyError[1] = 0; // set length to zero

  ptDbTrans->bRecalcTime = FALSE;

  // init Ethernet "if" parameters for both ports
  for (ii = 0; ii <= 1; ii++) {
    strcpy((char *)&ptProto->If.au8Descr[ii][2], "eth ");
    ptProto->If.au8Descr[ii][5] = ii + '0';
    ptProto->If.au8Descr[ii][0] = 0; // octet string length high byte
    ptProto->If.au8Descr[ii][1] = 4; // octet string length low byte
    ptProto->If.au8Type[ii] = 6;     // ethernet-csmacd
    ptProto->If.au32Mtu[ii] = SIZE_COMMSBLOCK;
    ptProto->If.au32Speed[ii] = 10000000;  // 10 Mbit
    ptProto->If.au8PhysAddress[ii][0] = 0; // set octet string length of 6 for MAC address, high byte is zero
    ptProto->If.au8PhysAddress[ii][1] = 6; // length low byte
    vGetMACAddress(&ptProto->If.au8Descr[ii][2], &ptProto->If.au8PhysAddress[ii][2]);
  }

  // initialize control objects which have non-zero defaults
  s8SetIVar1Byte_r(IVAR_ID__CIC_MODE, CIC_MODE_DISABLED, psATCsys->eCaptureFlag, &psTrafficIn->tIVars, &psTrafficIn->tIVarsTick);
  s8SetIVar1Byte_r(IVAR_ID__CIC_SYNC_REF_MODE, CIC_SYNC_REF_MODE_TIMEBASE, psATCsys->eCaptureFlag, &psTrafficIn->tIVars, &psTrafficIn->tIVarsTick);
  s8SetIVar1Byte_r(IVAR_ID__CONTROL_SYS_SYNC, 255, psATCsys->eCaptureFlag, &psTrafficIn->tIVars, &psTrafficIn->tIVarsTick);
  vResetControlTimerForSignals_r(psATCsys);
} // end InitOIDData()

//*******************************************************************************
//! returns the oidMax value from the OID table structure
//!
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//!
//! @remarks     used for read-only objects that return a fixed max value <br>
//!              oidMax is interpreted as an 32bit unsigned value
//*******************************************************************************
BOOLEAN actionMax(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                  INT8U **ptrResp,                          //!< [inout] response buffer
                  INT16U *sizResp,                          //!< [inout] response buffer size
                  BOOLEAN __attribute__((unused)) validate, //!< unused
                  INT16U *errorCode)                        //!< [out] return error code
{
  *errorCode = SNMPERRORNOERROR; // expect no errors
  return bAppendUInt(OID[ptrMsg->usObjectRow].oidMax, ptrResp, sizResp, errorCode);
}

//*******************************************************************************
//! returns the oidIndexMax[0] value from the OID table structure
//!
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//!
//! @remarks      used for read-only objects that return a fixed max value
//*******************************************************************************
BOOLEAN actionIdx1(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                   INT8U **ptrResp,                          //!< [inout] response buffer
                   INT16U *sizResp,                          //!< [inout] response buffer size
                   BOOLEAN __attribute__((unused)) validate, //!< unused
                   INT16U *errorCode)                        //!< [out] return error code
{
  *errorCode = SNMPERRORNOERROR; // expect no errors
  return bAppendUInt(ptrMsg->usObjectIndex[0], ptrResp, sizResp, errorCode);
}

//*******************************************************************************
//! returns the oidIndexMax[1] value from the OID table structure
//!
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//!
//! @remarks      used for read-only objects that return a fixed max value
//*******************************************************************************
BOOLEAN actionIdx2(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                   INT8U **ptrResp,                          //!< [inout] response buffer
                   INT16U *sizResp,                          //!< [inout] response buffer size
                   BOOLEAN __attribute__((unused)) validate, //!< unused
                   INT16U *errorCode)                        //!< [out] return error code
{
  *errorCode = SNMPERRORNOERROR; // expect no errors
  return bAppendUInt(ptrMsg->usObjectIndex[1], ptrResp, sizResp, errorCode);
}

//*******************************************************************************
//! function for sysUpTime object
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_sysUpTime(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                     INT8U **ptrResp,                          //!< [inout] response buffer
                     INT16U *sizResp,                          //!< [inout] response buffer size
                     BOOLEAN __attribute__((unused)) validate, //!< not used
                     INT16U *errorCode)                        //!< [out] return error code
{
  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    *errorCode = SNMPERRORREADONLY;
    return (FALSE);
  }

  // our upTime status is in seconds, sysUpTime is in hundredths so *100
  return (bAppendUInt(psATCsys->upTime * 100, ptrResp, sizResp, errorCode));
}

//*******************************************************************************
//! function for mcAtcDocVersion object
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
static BOOLEAN fn_mcAtcDocVersion(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                                  INT8U **ptrResp,                          //!< [inout] response buffer
                                  INT16U *sizResp,                          //!< [inout] response buffer size
                                  BOOLEAN __attribute__((unused)) validate, //!< not used
                                  INT16U *errorCode)                        //!< [out] return error code
{
  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    *errorCode = SNMPERRORREADONLY;
    return (FALSE);
  }
  return (bAppendUInt(BUILD_MIB, ptrResp, sizResp, errorCode));
}

/*************************************************************************************************/
/*  Name       : bFnShortAlarmStatus()                                                           */
/*                                                                                               */
/*  Description: function for shortAlarmStatus object                                            */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN bFnShortAlarmStatus(TYPE_COMMS_MSG __attribute__((unused)) * ptrMsg, //!< [inout] message structure holding received message
                            INT8U **ptrResp,                                 //!< [inout] response buffer
                            INT16U *sizResp,                                 //!< [inout] response buffer size
                            BOOLEAN __attribute__((unused)) validate,        //!< not used
                            INT16U *errorCode)                               //!< [out] return error code
{
  BOOLEAN bErr;

  bErr = bAppendUInt(psNtcipStatus->shortAlarmStatus, ptrResp, sizResp, errorCode);

  if (*errorCode == SNMPERRORNOERROR) {
    psNtcipStatus->shortAlarmStatus &= ~SHORTALRM_LOCAL_CYC_ZERO;
  }

  return (bErr);
}

//******************************************************************************
//! Action function
//! @return     TRUE on success
//******************************************************************************
BOOLEAN fn_hdlcGroupAddressNumber(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                                  INT8U **ptrResp,        //!< [inout] response buffer
                                  INT16U *sizResp,        //!< [inout] response buffer size
                                  BOOLEAN validate,       //!< only perform dry-run write if set
                                  INT16U *errorCode)      //!< [out] return error code
{ 
  INT8U tmp = 0;
  INT16U idx1 = ptrMsg->usObjectIndex[0] - 1;

  *errorCode = SNMPERRORNOERROR; // expect no errors

  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &tmp, errorCode)) {
      if ((tmp < OID[ptrMsg->usObjectRow].oidMin) || (tmp > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      // NUM_HDLCGROUPADDRESSS (maps 1-to-1 to serial ports, then to Ethernet ports)
      if (idx1 < NUM_RS232PORTS) {
        ptrMsg->ptNtcipParameters->serialPorts[idx1].mcAtcSerialGroupAddress = tmp;
      } else { // idx1 must be < (NUM_RS232PORTS+NUM_ETHERNETPORTS) due to index range check
        idx1 -= NUM_RS232PORTS;
        ptrMsg->ptNtcipParameters->enetPorts[idx1].mcAtcEthernetAB3418GroupAddr = tmp;
      }
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(tmp, ptrResp, sizResp, errorCode);
    } else {
      return (FALSE);
    }
  }
  // NUM_HDLCGROUPADDRESSS (maps 1-to-1 to serial ports, then to Ethernet ports)
  if (idx1 < NUM_RS232PORTS) {
    tmp = ptrMsg->ptNtcipParameters->serialPorts[idx1].mcAtcSerialGroupAddress;
  } else { // idx1 must be < (NUM_RS232PORTS+NUM_ETHERNETPORTS) due to index range check
    idx1 -= NUM_RS232PORTS;
    tmp = ptrMsg->ptNtcipParameters->enetPorts[idx1].mcAtcEthernetAB3418GroupAddr;
  }
  return bAppendUInt(tmp, ptrResp, sizResp, errorCode);
}

//******************************************************************************
//! Action function to handle standard ASC split table
//! Note: Action function is required because the db array sizes do not match MAX_SPLITS
//! @return     TRUE on success
//******************************************************************************
BOOLEAN fn_ascSplitTable(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                         INT8U **ptrResp,        //!< [inout] response buffer
                         INT16U *sizResp,        //!< [inout] response buffer size
                         BOOLEAN validate,       //!< only perform dry-run write if set
                         INT16U *errorCode)      //!< [out] return error code
{
  INT16U idx1 = ptrMsg->usObjectIndex[0] - 1;
  INT16U idx2 = ptrMsg->usObjectIndex[1] - 1;
  INT8U ucValue = 0;

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
      if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
        case 3: // splitTime
          ptrMsg->ptNtcipParameters->splitTime[idx1][idx2] = ucValue;
          break;
        case 4: // splitMode
          ptrMsg->ptNtcipParameters->splitMode[idx1][idx2] = ucValue;
          break;
        case 5: // splitCoordPhase
          ptrMsg->ptNtcipParameters->splitCoordPhase[idx1][idx2] = ucValue;
          break;
        default:
          *errorCode = SNMPERRORNOSUCHNAME;
          return (FALSE);
      }
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
    } else {
      return (FALSE);
    }
  }

  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 3: // splitTime
      return bAppendUInt(ptrMsg->ptNtcipParameters->splitTime[idx1][idx2], ptrResp, sizResp, errorCode);
    case 4: // splitMode
      return bAppendUInt(ptrMsg->ptNtcipParameters->splitMode[idx1][idx2], ptrResp, sizResp, errorCode);
    case 5: // splitCoordPhase
      return bAppendUInt(ptrMsg->ptNtcipParameters->splitCoordPhase[idx1][idx2], ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
}

//******************************************************************************
//! Action function to handle McCain split table
//! Note: Action function is required because the db array sizes do not match MAX_SPLITS
//! @return     TRUE on success
//******************************************************************************
BOOLEAN fn_mcSplitTable(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                        INT8U **ptrResp,        //!< [inout] response buffer
                        INT16U *sizResp,        //!< [inout] response buffer size
                        BOOLEAN validate,       //!< only perform dry-run write if set
                        INT16U *errorCode)      //!< [out] return error code
{
  INT16U idx1 = ptrMsg->usObjectIndex[0] - 1;
  INT16U idx2 = ptrMsg->usObjectIndex[1] - 1;
  INT8U ucValue = 0;
  // INT16U  usValue;

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
      if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
        case 1: // mcAtcCoordSplitManualPermit
          ptrMsg->ptNtcipParameters->mcAtcCoordSplitManualPermit[idx1][idx2] = ucValue;
          break;
        case 2: // mcAtcCoordSplitManualOmit
          ptrMsg->ptNtcipParameters->mcAtcCoordSplitManualOmit[idx1][idx2] = ucValue;
          break;
        case 3: // mcAtcCoordSplitMinTime
          ptrMsg->ptNtcipParameters->mcAtcCoordSplitMinTime[idx1][idx2] = ucValue;
          break;
        case 4: // mcAtcSplitMode (same db value as ASC splitMode)
          ptrMsg->ptNtcipParameters->splitMode[idx1][idx2] = ucValue;
          break;
        case 5: // mcAtcCoordSplitMaxReserviceCount
          ptrMsg->ptNtcipParameters->mcAtcCoordSplitMaxReserviceCount[idx1][idx2] = ucValue;
          break;
        case 6: // mcAtcCoordSplitBeginReservice
          ptrMsg->ptNtcipParameters->mcAtcCoordSplitBeginReservice[idx1][idx2] = ucValue;
          break;
        case 7: // mcAtcCoordSplitEndReservice
          ptrMsg->ptNtcipParameters->mcAtcCoordSplitEndReservice[idx1][idx2] = ucValue;
          break;
        default:
          *errorCode = SNMPERRORNOSUCHNAME;
          return (FALSE);
      }
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
    } else {
      return (FALSE);
    }
  }

  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 1: // mcAtcCoordSplitManualPermit
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcCoordSplitManualPermit[idx1][idx2], ptrResp, sizResp, errorCode);
    case 2: // mcAtcCoordSplitManualOmit
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcCoordSplitManualOmit[idx1][idx2], ptrResp, sizResp, errorCode);
    case 3: // mcAtcCoordSplitMinTime
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcCoordSplitMinTime[idx1][idx2], ptrResp, sizResp, errorCode);
    case 4: // mcAtcSplitMode  (same db value as ASC splitMode)
      return bAppendUInt(ptrMsg->ptNtcipParameters->splitMode[idx1][idx2], ptrResp, sizResp, errorCode);
    case 5: // mcAtcCoordSplitMaxReserviceCount
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcCoordSplitMaxReserviceCount[idx1][idx2], ptrResp, sizResp, errorCode);
    case 6: // mcAtcCoordSplitBeginReservice
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcCoordSplitBeginReservice[idx1][idx2], ptrResp, sizResp, errorCode);
    case 7: // mcAtcCoordSplitEndReservice
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcCoordSplitEndReservice[idx1][idx2], ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
}

//******************************************************************************
//! Action function
//! @return     TRUE on success
//******************************************************************************
BOOLEAN fn_sequenceData(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                        INT8U **ptrResp,        //!< [inout] response buffer
                        INT16U *sizResp,        //!< [inout] response buffer size
                        BOOLEAN validate,       //!< only perform dry-run write if set
                        INT16U *errorCode)      //!< [out] return error code
{
  INT8U anOCTETvalue[RING_SEQUENCE_SIZE];
  INT16U idx1 = ptrMsg->usObjectIndex[0] - 1;
  INT16U idx2 = ptrMsg->usObjectIndex[1] - 1;
  INT8U u8Index = 0;

  memset(anOCTETvalue, 0, sizeof(anOCTETvalue));

  *errorCode = SNMPERRORNOERROR; // expect no errors

  if (ptrMsg->boIsWriteTheValue) {
    ptrMsg->usCurrentDataSize = sizeof(anOCTETvalue);
    if (bDecodeOctetValue(&ptrMsg->ucReadPointer, anOCTETvalue, &ptrMsg->usCurrentDataSize, errorCode)) {
      if (validate) {
        return (TRUE);
      }

      // check valid range phases used in anOCTETvalue array (valid range is [ 1 .. MAX_PHASES] )
      for (u8Index = 0; u8Index < ptrMsg->usCurrentDataSize; u8Index++) { // check up to Octet size received
        // set BadValue error if any value makes reference to a phase number out of the valid range
        if (anOCTETvalue[u8Index] < 1 || anOCTETvalue[u8Index] > MAX_PHASES) {
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
      }
      ptrMsg->ptNtcipParameters->sequenceData[idx1][idx2][0] = (INT8U)(ptrMsg->usCurrentDataSize >> 8);
      ptrMsg->ptNtcipParameters->sequenceData[idx1][idx2][1] = (INT8U)ptrMsg->usCurrentDataSize;

      // copy the whole octet string array so any zero fill at the end is also copied
      memcpy(&ptrMsg->ptNtcipParameters->sequenceData[idx1][idx2][2], anOCTETvalue, RING_SEQUENCE_SIZE);

      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }

      /// could call MSG_SetOidOCTValue (ptrMsg->usObjectRow, ptrMsg->usObjectIndex, ptrMsg->usCurrentDataSize, anOCTETvalue, errorCode);
      /// for a single place to write octet strings, but would be less efficient due to redundant checks

      return bAppendOctet(&ptrMsg->ptNtcipParameters->sequenceData[idx1][idx2][2], ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    } else {
      return (FALSE);
    }
  }
  ptrMsg->usCurrentDataSize = (ptrMsg->ptNtcipParameters->sequenceData[idx1][idx2][0] << 8) | ptrMsg->ptNtcipParameters->sequenceData[idx1][idx2][1];
  return bAppendOctet(&ptrMsg->ptNtcipParameters->sequenceData[idx1][idx2][2], ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
}

//*******************************************************************************
//! convert an octet string of phase numbers to a PHASEBITS variable
//! and save to memory
//!
//! @return      TRUE if successful, otherwise FALSE
//!
//! @remarks     The phases must be 1 to MAX_PHASES, must be in order, and must not be repeated.
//!              A zero is also allowed as a way of clearing all phasebits
//*******************************************************************************
BOOLEAN octStr2phaseBits(const INT8U *srcStr,  //!< [in] the source octet string of phase numbers
                         INT16U dataSize,      //!< the length of the octet string
                         PHASEBITS *phaseBits) //!< [out] pointer to the PHASEBITS variable to write
{
  PHASEBITS tempBits = 0;
  INT8U lastPhase = 0;
  int ii = 0;

  // allow a zero to be set
  if (dataSize == 1 && srcStr[0] == 0) {
    *phaseBits = 0;
    return TRUE;
  }

  for (ii = 0; ii < dataSize; ii++) {
    if ((srcStr[ii] <= MAX_PHASES) && (srcStr[ii] > lastPhase)) { // this check also disallows phase value of zero in the octet string
      tempBits |= 1 << (srcStr[ii] - 1);                          // phase values are 1 to MAX_PHASES, so -1 for shift
      lastPhase = srcStr[ii];
    } else {
      return FALSE;
    }
  }
  *phaseBits = tempBits;
  return TRUE;
} // end octStr2phaseBits()

//*******************************************************************************
//! convert a PHASEBITS variable to an octet string of phase numbers
//!
//! @return       length of the octet string
//!
//! @remarks      returned length will be zero if no phase bits set
//*******************************************************************************
INT16U phaseBits2octStr(PHASEBITS phaseBits, //!< the PHASEBITS variable to convert
                        INT8U *destStr)      //!< [out] destination buffer (must be at least MAX_PHASES long to guarantee enough space)
{
  PHASEBITS phaseMask = 1;
  int zphase = 0; // zero-based phase index
  INT16U dataSize = 0;

  for (zphase = 0; zphase < MAX_PHASES; zphase++) {
    if (phaseBits & phaseMask) {
      *destStr++ = zphase + 1;
      dataSize++;
    }
    phaseMask <<= 1;
  }
  return (dataSize);
} // end phaseBits2octStr()

//*******************************************************************************
//! convert an octet string of overlap numbers to a OVERLAPBITS variable
//! and save to memory
//!
//! @return      TRUE if successful, otherwise FALSE
//!
//! @remarks  The overlaps must be 1 to MAX_VEH_OVERLAPS, must be in order, and must not be repeated.
//*******************************************************************************
BOOLEAN octStr2overlapBits(const INT8U *srcStr,      //!< [in] the source octet string of overlap numbers
                           INT16U dataSize,          //!< the length of the octet string
                           OVERLAPBITS *overlapBits) //!< [out] pointer to the OVERLAPBITS variable to write
{
  OVERLAPBITS tempBits = 0;
  INT8U lastOverlap = 0;
  int ii = 0;

  for (ii = 0; ii < dataSize; ii++) {
    if ((srcStr[ii] <= MAX_VEH_OVERLAPS) && (srcStr[ii] > lastOverlap)) { // this check also disallows overlap value of zero in the octet string
      tempBits |= 1 << (srcStr[ii] - 1);                                  // overlap values are 1 to MAX_VEH_OVERLAPS, so -1 for shift
    } else {
      return (FALSE);
    }
  }
  *overlapBits = tempBits;
  return (TRUE);
} // end octStr2overlapBits()

//*******************************************************************************
//! convert a OVERLAPBITS variable to an octet string of overlap numbers
//!
//! @return       length of the octet string
//!
//! @remarks      returned length will be zero if no overlap bits set
//*******************************************************************************
INT16U overlapBits2octStr(OVERLAPBITS overlapBits, //!< the OVERLAPBITS variable to convert
                          INT8U *destStr)          //!< [out] destination buffer
{
  OVERLAPBITS overlapMask = 1;
  int zoverlap = 0; // zero-based overlap index
  INT16U dataSize = 0;

  for (zoverlap = 0; zoverlap < MAX_VEH_OVERLAPS; zoverlap++) {
    if (overlapBits & overlapMask) {
      *destStr++ = zoverlap + 1;
      dataSize++;
    }
    overlapMask <<= 1;
  }
  return (dataSize);
} // end overlapBits2octStr()

//*******************************************************************************
//! function for overlapIncludedPhases object
//!
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//!
//! Note: Standard 1202 object has single index, references data in first overlap set
//*******************************************************************************
BOOLEAN fn_overlapIncludedPhases(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                                 INT8U **ptrResp,        //!< [inout] response buffer
                                 INT16U *sizResp,        //!< [inout] response buffer size
                                 BOOLEAN validate,       //!< only perform dry-run write if set
                                 INT16U *errorCode)      //!< [out] return error code
{
  INT8U anOCTETvalue[MAX_PHASES];
  INT16U idx1 = ptrMsg->usObjectIndex[0] - 1;

  memset(anOCTETvalue, 0, sizeof(anOCTETvalue));

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {
    ptrMsg->usCurrentDataSize = sizeof(anOCTETvalue);
    if (bDecodeOctetValue(&ptrMsg->ucReadPointer, anOCTETvalue, &ptrMsg->usCurrentDataSize, errorCode)) {
      if (validate) {
        return TRUE;
      }
      if (octStr2phaseBits(anOCTETvalue, ptrMsg->usCurrentDataSize, &ptrMsg->ptNtcipParameters->atOverlapData[0].atVehOverlaps[idx1].overlapIncludedPhases)) {
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      } else {
        *errorCode = SNMPERRORBADVALUE;
        return FALSE;
      }
    } else {
      return (FALSE); // errorCode set by bDecodeOctetValue
    }
  }
  ptrMsg->usCurrentDataSize = phaseBits2octStr(ptrMsg->ptNtcipParameters->atOverlapData[0].atVehOverlaps[idx1].overlapIncludedPhases, anOCTETvalue); // xx doesn't check if receiving buffer is large enough
  return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
}

//*******************************************************************************
//! function for overlapModifierPhases object
//!
//! ARGUMENTS  :  ptrMsg  - pointer to message structure holding received message
//!               ptrResp - pointer to message structure to hold response
//!               errorCode - returns error code if there is an error
//!
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//!
//! Note: Standard 1202 object has single index, references data in first overlap set
//*******************************************************************************
BOOLEAN fn_overlapModifierPhases(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                                 INT8U **ptrResp,        //!< [inout] response buffer
                                 INT16U *sizResp,        //!< [inout] response buffer size
                                 BOOLEAN validate,       //!< only perform dry-run write if set
                                 INT16U *errorCode)      //!< [out] return error code
{
  INT8U anOCTETvalue[MAX_PHASES];
  INT16U idx1 = ptrMsg->usObjectIndex[0] - 1;

  memset(anOCTETvalue, 0, sizeof(anOCTETvalue));

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {
    ptrMsg->usCurrentDataSize = sizeof(anOCTETvalue);
    if (bDecodeOctetValue(&ptrMsg->ucReadPointer, anOCTETvalue, &ptrMsg->usCurrentDataSize, errorCode)) {
      if (validate) {
        return (TRUE);
      }
      if (octStr2phaseBits(anOCTETvalue, ptrMsg->usCurrentDataSize, &ptrMsg->ptNtcipParameters->atOverlapData[0].atVehOverlaps[idx1].overlapModifierPhases)) {
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      } else {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
    } else {
      return (FALSE); // errorCode set by bDecodeOctetValue
    }
  }
  ptrMsg->usCurrentDataSize = phaseBits2octStr(ptrMsg->ptNtcipParameters->atOverlapData[0].atVehOverlaps[idx1].overlapModifierPhases, anOCTETvalue);
  return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
}

/*************************************************************************************************/
/*  Name       : bLocalCycleTime.                                                                */
/*                                                                                               */
/*  Description: Function for localCycleTimer and localCycleLength objects.                      */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN bLocalCycleTime(TYPE_COMMS_MSG *ptMsg,                     //!< [inout] message structure holding received message
                        INT8U **ppu8Resp,                          //!< [inout] response buffer
                        INT16U *pu16SizResp,                       //!< [inout] response buffer size
                        BOOLEAN __attribute__((unused)) bValidate, //!< not used
                        INT16U *puErrorCode)                       //!< [out] return error code
{

  *puErrorCode = SNMPERRORNOERROR;
  if (ptMsg->boIsWriteTheValue) {
    *puErrorCode = SNMPERRORREADONLY;
    return (FALSE);
  }
  switch (OID[ptMsg->usObjectRow].oidPart[6]) {
    case 7: // mcAtclocalCycleTimer
      return bAppendUInt((psTrafficOut->localCycleTimer / 10), ppu8Resp, pu16SizResp, puErrorCode);
    case 13: // mcAtclocalCycleLength
      return bAppendUInt(psTrafficOut->localCycleLength, ppu8Resp, pu16SizResp, puErrorCode);
    default: // This shouldn't happen
      *puErrorCode = SNMPERRORNOSUCHNAME;
      break;
  }

  return FALSE;
} // end bLocalCycleTime()

//*******************************************************************************
//! function for ped overlap parameters
//!
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_pedOverlapParms(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                           INT8U **ptrResp,        //!< [inout] response buffer
                           INT16U *sizResp,        //!< [inout] response buffer size
                           BOOLEAN validate,       //!< only perform dry-run write if set
                           INT16U *errorCode)      //!< [out] return error code
{
  INT8U ucValue = 0;
  INT16U usValue = 0;
  INT8U anOCTETvalue[MAX_PHASES];

  memset(anOCTETvalue, 0, sizeof(anOCTETvalue));

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 8:  // mcAtcPedOverlapWalkTime
      case 9:  // mcAtcPedOverlapClearanceTime
      case 10: // mcAtcPedOverlapRecall
        if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
          if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;

      case 3: // mcAtcPedOverlapIncludedPhases
      case 4: // mcAtcPedOverlapExcludedPhases
        ptrMsg->usCurrentDataSize = sizeof(anOCTETvalue);
        if (bDecodeOctetValue(&ptrMsg->ucReadPointer, anOCTETvalue, &ptrMsg->usCurrentDataSize, errorCode)) {
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;

      case 6: // mcAtcPedOverlapCallPhases
        if (bDecodeUInt2(&ptrMsg->ucReadPointer, &usValue, errorCode)) {
          if ((usValue < OID[ptrMsg->usObjectRow].oidMin) || (usValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;

      default:
        break;
    }
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 3: // mcAtcPedOverlapIncludedPhases
        if (!octStr2phaseBits(anOCTETvalue, ptrMsg->usCurrentDataSize, &ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atPedOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcPedOverlapIncludedPhases)) {
          // the conversion failed
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      case 4: // mcAtcPedOverlapExcludedPhases
        if (!octStr2phaseBits(anOCTETvalue, ptrMsg->usCurrentDataSize, &ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atPedOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcPedOverlapExcludedPhases)) {
          // the conversion failed
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      case 6: // mcAtcPedOverlapCallPhases
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atPedOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcPedOverlapCallPhases = usValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(usValue, ptrResp, sizResp, errorCode);
      case 8: // mcAtcPedOverlapWalkTime
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atPedOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcPedOverlapWalkTime = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      case 9: // mcAtcPedOverlapClearanceTime
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atPedOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcPedOverlapClearanceTime = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      case 10: // mcAtcPedOverlapRecall
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atPedOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcPedOverlapRecall = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      default:
        *errorCode = SNMPERRORNOSUCHNAME;
        return (FALSE);
    }
  }

  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 3: // mcAtcPedOverlapIncludedPhases
      ptrMsg->usCurrentDataSize = phaseBits2octStr(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atPedOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcPedOverlapIncludedPhases, anOCTETvalue);
      return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    case 4: // mcAtcPedOverlapExcludedPhases
      ptrMsg->usCurrentDataSize = phaseBits2octStr(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atPedOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcPedOverlapExcludedPhases, anOCTETvalue);
      return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    case 6: // mcAtcPedOverlapCallPhases
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atPedOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcPedOverlapCallPhases, ptrResp, sizResp, errorCode);
    case 8: // mcAtcPedOverlapWalkTime
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atPedOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcPedOverlapWalkTime, ptrResp, sizResp, errorCode);
    case 9: // mcAtcPedOverlapClearanceTime
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atPedOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcPedOverlapClearanceTime, ptrResp, sizResp, errorCode);
    case 10: // mcAtcPedOverlapRecall
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atPedOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcPedOverlapRecall, ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_pedOverlapParms()

//******************************************************************************
//! Action function for channelFlash object.
//! @return     TRUE on success
//******************************************************************************
BOOLEAN fn_channelFlash(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                        INT8U **ptrResp,        //!< [inout] response buffer
                        INT16U *sizResp,        //!< [inout] response buffer size
                        BOOLEAN validate,       //!< only perform dry-run write if set
                        INT16U *errorCode)      //!< [out] return error code
{
  INT8U tmp = 0;
  INT16U idx1 = ptrMsg->usObjectIndex[0] - 1; // index has already been range checked before get here

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &tmp, errorCode)) {
      if (tmp & 0xF1) { // bit 0 and bits 4 - 7 are reserved, return bad value if try to set them to 1
        *errorCode = SNMPERRORBADVALUE;
        return FALSE;
      }
      if ((tmp & 0x06) == 0x06) { // if try to set both bit 1 (flash yel) and bit 2 (flash red) the force only flash red per NTCIP 1202 v02.18
        tmp &= ~0x02;             // remove the flash yellow bit 1
      }
      if (validate) {
        return TRUE;
      }
      ptrMsg->ptNtcipParameters->channelFlash[idx1] = tmp;
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(ptrMsg->ptNtcipParameters->channelFlash[idx1], ptrResp, sizResp, errorCode);
    } else {
      return FALSE;
    }
  }
  return bAppendUInt(ptrMsg->ptNtcipParameters->channelFlash[idx1], ptrResp, sizResp, errorCode);
} // end fn_channelFlash()

//******************************************************************************
//! Action function for channelDim object.
//! @return     TRUE on success
//******************************************************************************
BOOLEAN fn_channelDim(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                      INT8U **ptrResp,        //!< [inout] response buffer
                      INT16U *sizResp,        //!< [inout] response buffer size
                      BOOLEAN validate,       //!< only perform dry-run write if set
                      INT16U *errorCode)      //!< [out] return error code
{
  INT8U tmp = 0;
  INT16U idx1 = ptrMsg->usObjectIndex[0] - 1; // index has already been range checked before get here

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &tmp, errorCode)) {
      if (tmp & 0xF0) { // bits 4 - 7 are reserved, return bad value if try to set them to 1
        *errorCode = SNMPERRORBADVALUE;
        return FALSE;
      }
      if (validate) {
        return TRUE;
      }
      ptrMsg->ptNtcipParameters->channelDim[idx1] = tmp;
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(ptrMsg->ptNtcipParameters->channelDim[idx1], ptrResp, sizResp, errorCode);
    } else {
      return FALSE;
    }
  }
  return bAppendUInt(ptrMsg->ptNtcipParameters->channelDim[idx1], ptrResp, sizResp, errorCode);
} // end fn_channelDim()

//******************************************************************************
//! Action function
//! @return     TRUE on success
//******************************************************************************
BOOLEAN fn_dayPlanHour(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                       INT8U **ptrResp,        //!< [inout] response buffer
                       INT16U *sizResp,        //!< [inout] response buffer size
                       BOOLEAN validate,       //!< only perform dry-run write if set
                       INT16U *errorCode)      //!< [out] return error code
{
  INT8U tmp = 0;
  INT16U idx1 = ptrMsg->usObjectIndex[0] - 1;
  INT16U idx2 = ptrMsg->usObjectIndex[1] - 1;

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &tmp, errorCode)) {
      if ((tmp < OID[ptrMsg->usObjectRow].oidMin) || (tmp > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      ptrMsg->ptNtcipParameters->tTod.tDayPlan[idx1][idx2].u8DayPlanHour = tmp;
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(ptrMsg->ptNtcipParameters->tTod.tDayPlan[idx1][idx2].u8DayPlanHour, ptrResp, sizResp, errorCode);
    } else {
      return (FALSE);
    }
  }
  return bAppendUInt(ptrMsg->ptNtcipParameters->tTod.tDayPlan[idx1][idx2].u8DayPlanHour, ptrResp, sizResp, errorCode);
}

//******************************************************************************
//! Action function
//! @return     TRUE on success
//******************************************************************************
BOOLEAN fn_dayPlanMinute(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                         INT8U **ptrResp,        //!< [inout] response buffer
                         INT16U *sizResp,        //!< [inout] response buffer size
                         BOOLEAN validate,       //!< only perform dry-run write if set
                         INT16U *errorCode)      //!< [out] return error code
{
  INT8U tmp = 0;
  INT16U idx1 = ptrMsg->usObjectIndex[0] - 1;
  INT16U idx2 = ptrMsg->usObjectIndex[1] - 1;

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &tmp, errorCode)) {
      if ((tmp < OID[ptrMsg->usObjectRow].oidMin) || (tmp > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      ptrMsg->ptNtcipParameters->tTod.tDayPlan[idx1][idx2].u8DayPlanMinute = tmp;
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(ptrMsg->ptNtcipParameters->tTod.tDayPlan[idx1][idx2].u8DayPlanMinute, ptrResp, sizResp, errorCode);
    } else {
      return (FALSE);
    }
  }
  return bAppendUInt(ptrMsg->ptNtcipParameters->tTod.tDayPlan[idx1][idx2].u8DayPlanMinute, ptrResp, sizResp, errorCode);
}

//*******************************************************************************
//! action function for object dayPlanActionNumberOID
//!
//! @return      TRUE if successful, otherwise FALSE
//!
//! @remarks     This object is passed by NTCIP as an OID with an  appended index,
//!   but since the OID is fixed we only store the index in shared memory.
//*******************************************************************************
BOOLEAN fn_dayPlanActionNumberOID(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                                  INT8U **ptrResp,        //!< [inout] response buffer
                                  INT16U *sizResp,        //!< [inout] response buffer size
                                  BOOLEAN validate,       //!< only perform dry-run write if set
                                  INT16U *errorCode)      //!< [out] return error code
{
  INT8U anOIDvalue[SIZE_ACTIONOID];
  INT16U idx1;
  INT16U idx2;
  INT16U bufLeft = 0;
  INT16U tbcAction = 0;
  const INT8U actionOID[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x89, 0x36, 0x04, 0x02, 0x01, 0x05, 0x03, 0x01, 0x01}; // OID for timebaseAscActionNumber
  const INT16U actionOIDsize = sizeof(actionOID);

  memset(anOIDvalue, 0, sizeof(anOIDvalue));

  const INT8U *ptr = &anOIDvalue[actionOIDsize];

  *errorCode = SNMPERRORNOERROR;
  idx1 = ptrMsg->usObjectIndex[0] - 1;
  idx2 = ptrMsg->usObjectIndex[1] - 1;
  if (ptrMsg->boIsWriteTheValue) { // See if it is a write
    ptrMsg->usCurrentDataSize = sizeof(anOIDvalue);
    if (bDecodeOIDValue(&ptrMsg->ucReadPointer, anOIDvalue, &ptrMsg->usCurrentDataSize, errorCode)) {
      if (ptrMsg->usCurrentDataSize == 0) {
        if (validate) {
          return (TRUE);
        }
        ptrMsg->ptNtcipParameters->tTod.tDayPlan[idx1][idx2].u8DayPlanActionNumberOID = 0; // Accept a zero-length OID string as disabling the day plan event, set action index to zero
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) {                                     // Skip response in decode mode.
          return TRUE;
        }
        // no action index, return an empty (zero length) OID string
        memset(anOIDvalue, 0, actionOIDsize); // zero buffer for length of timebaseAscActionNumber OID
        return bAppendOID(anOIDvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      } else if ((ptrMsg->usCurrentDataSize > actionOIDsize)            // Check that there are more elements in the oid string after the action oid
                 && (memcmp(anOIDvalue, actionOID, actionOIDsize) == 0) // Check that OID matches timebaseAscActionNumber
      ) {
        ptr = &anOIDvalue[actionOIDsize];
        bufLeft = ptrMsg->usCurrentDataSize - actionOIDsize;
        if (bDecodOIDSubidentifier(&ptr, &bufLeft, (INT16S *)(&tbcAction), errorCode)) {
          if ((tbcAction >= 1) && (tbcAction <= MAX_TBC_ACTIONS)) { // Check that action index is within allowed range
            if (validate) {
              return (TRUE);
            }
            ptrMsg->ptNtcipParameters->tTod.tDayPlan[idx1][idx2].u8DayPlanActionNumberOID = (INT8U)tbcAction;
            if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
              return TRUE;
            }
            // set up return value
            if (tbcAction == 0) {
              // no action index, return an empty (zero length) OID string
              memset(anOIDvalue, 0, actionOIDsize); // zero buffer for length of timebaseAscActionNumber OID
              ptrMsg->usCurrentDataSize = 0;        // set length to zero
            } else {
              memcpy(anOIDvalue, actionOID, actionOIDsize); // length of timebaseAscActionNumber OID
              ptrMsg->usCurrentDataSize = actionOIDsize;    // assign the length

              if (tbcAction > 127) { // as soon as the action number index becomes greater than 127 it takes more than one byte to encode the oid subidentifier
                anOIDvalue[ptrMsg->usCurrentDataSize++] = 0x81;
              }
              anOIDvalue[ptrMsg->usCurrentDataSize++] = (INT8U)(tbcAction & 0x7F); // assign the lowest 7 bits
            }
            return bAppendOID(anOIDvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
          } else {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
        } else {
          return (FALSE); // return error set by bDecodOIDSubidentifier()
        }
      } else {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
    } else {
      return (FALSE);
    }
  }
  // For the return data, have to build up the OID string by appending the action index
  tbcAction = ptrMsg->ptNtcipParameters->tTod.tDayPlan[idx1][idx2].u8DayPlanActionNumberOID;
  if (tbcAction == 0) {
    // no action index, return an empty (zero length) OID string
    memset(anOIDvalue, 0, actionOIDsize); // zero buffer for length of timebaseAscActionNumber OID
    ptrMsg->usCurrentDataSize = 0;        // set length to zero
  } else {
    memcpy(anOIDvalue, actionOID, actionOIDsize); // length of timebaseAscActionNumber OID
    ptrMsg->usCurrentDataSize = actionOIDsize;    // assign the length

    if (tbcAction > 127) { // as soon as the action number index becomes greater than 127 it takes more than one byte to encode the oid subidentifier
      anOIDvalue[ptrMsg->usCurrentDataSize++] = 0x81;
    }
    anOIDvalue[ptrMsg->usCurrentDataSize++] = (INT8U)(tbcAction & 0x7F); // assign the lowest 7 bits
  }
  return bAppendOID(anOIDvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
}

//*******************************************************************************
//! function for controllerBaseStandards object
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_controllerBaseStandards(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                                   INT8U **ptrResp,                          //!< [inout] response buffer
                                   INT16U *sizResp,                          //!< [inout] response buffer size
                                   BOOLEAN __attribute__((unused)) validate, //!< not used
                                   INT16U *errorCode)                        //!< [out] return error code
{
  static const char *standardsStr = STR_CONTROLLERBASESTANDARDS; // see atc.h

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    *errorCode = SNMPERRORREADONLY;
    return (FALSE);
  }
  return bAppendOctet((INT8U *)standardsStr, ptrResp, sizResp, strlen(standardsStr), errorCode);
}

//*******************************************************************************
//! function for VOS log number of entries
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_VOSLogNumEntries(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                            INT8U **ptrResp,                          //!< [inout] response buffer
                            INT16U *sizResp,                          //!< [inout] response buffer size
                            BOOLEAN __attribute__((unused)) validate, //!< not used
                            INT16U *errorCode)                        //!< [out] return error code
{
  // Variables that are specific to log type
  TYPE_log_header head;
  const char *logFileName = SNAP_DET_VOS_LOG;

  // Variables that are generic for all log types
  FILE *logFp = NULL;
  int numEntries = 0;

  memset(&head, 0, sizeof(head));

  if (ptrMsg->boIsWriteTheValue) {
    *errorCode = SNMPERRORREADONLY;
    return (FALSE);
  }

  // check if this is a GETNEXT request, just return zero to avoid file errors that would abort a MIB walk
  if (ptrMsg->usInPDUtype == SNMPREQUESTGETNEXT) { // Check for GET NEXT
    *errorCode = SNMPERRORNOERROR;
    return bAppendUInt(0, ptrResp, sizResp, errorCode); // return zero
  }

  // check to see if start position is set
  if ((psNtcipStatus->detVOSLogCurReadPointer == -1) || (psATCsys->upTime > psNtcipStatus->detVOSLogLockoutTime)) {
    // start position not set or not valid anymore
    // This is an unconventional use of BadValue, but we wanted a unique error code
    *errorCode = SNMPERRORBADVALUE;
    return (FALSE);
  }

  // open log file in SRAM (file should always exist)
  logFp = fopen(logFileName, "r");
  if (logFp == NULL) {
    *errorCode = SNMPERRORGENERALERROR;
    return (FALSE);
  }

  // read header (there should always be a valid header)
  if (fread(&head, sizeof(head), 1, logFp) != 1) {
    *errorCode = SNMPERRORGENERALERROR;
    fclose(logFp);
    return (FALSE);
  }
  fclose(logFp);

  numEntries = head.numEntries - psNtcipStatus->detVOSLogCurReadPointer;
  if (numEntries < 0) {
    *errorCode = SNMPERRORGENERALERROR;
    return FALSE;
  }

  *errorCode = SNMPERRORNOERROR;
  return bAppendUInt((INT32U)numEntries, ptrResp, sizResp, errorCode);
} // end fn_VOSLogNumEntries()

//*******************************************************************************
//! function for VOS log reading
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_VOSLogReadAction(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                            INT8U **ptrResp,                          //!< [inout] response buffer
                            INT16U *sizResp,                          //!< [inout] response buffer size
                            BOOLEAN __attribute__((unused)) validate, //!< not used
                            INT16U *errorCode)                        //!< [out] return error code
{
  // Variables that are specific to log type
  TYPE_log_header head;
  TYPE_VOS_log_entry logRecord;
  const char *logFileName = SNAP_DET_VOS_LOG;

  // Variables that are generic for all log types
  long filePosition = 0;
  FILE *logFp = NULL; //!< file descriptor for log
  INT32U value = 0;
  BOOLEAN isSeqNum = FALSE; // true if requested value is sequence number, else it is a timestamp
  INT16U size = 0;
  int recordNumber = 0;
  int recordsSearched = 0;

  memset(&head, 0, sizeof(head));
  memset(&logRecord, 0, sizeof(logRecord));

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {

    if (!bDecodeGaugeValue(&ptrMsg->ucReadPointer, &value, &size, errorCode)) {
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }
    if (value == 0) {
      // Clear start position
      psNtcipStatus->detVOSLogCurReadPointer = -1;
      psNtcipStatus->detVOSLogLockoutTime = 0;
      ptVSMLog->u32VosLogStartSeqNum = 0;
      ptVSMLog->u32VosLogStartTimestamp = 0;
      // delete the snapshot of the log if one exists (ignore output and errors)
      if (system("rm -f " SNAP_DET_VOS_LOG " >/dev/null 2>&1") == -1) {
        vMcSysLog(LOG_ERR, "Failed to remove temp directory: %s", SNAP_DET_VOS_LOG);
      }
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
    } else if (psATCsys->upTime < psNtcipStatus->detVOSLogLockoutTime) {
      // Don't allow start position to be changed if lockout timer is active
      *errorCode = SNMPERRORREADONLY;
      return (FALSE);
    }

    // take a snapshot of the log
    remove(SNAP_DET_VOS_LOG); // delete the snapshot of the log if one exists (ignore errors)
    // Copy the file
    pthread_mutex_lock(&(psATCsys->workingVOSLogMutex));
    if (!(bCopyFile((CHAR *)(WFN_DET_VOS_LOG), (CHAR *)(SNAP_DET_VOS_LOG)))) { //, sizeof(logRecord)))) {
      pthread_mutex_unlock(&(psATCsys->workingVOSLogMutex));
      psNtcipStatus->detVOSLogCurReadPointer = -1;
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }
    psNtcipStatus->detVOSLogSnapshotTaken = TRUE;
    pthread_mutex_unlock(&(psATCsys->workingVOSLogMutex));

    // open log file in SRAM (file should always exist)
    logFp = fopen(logFileName, "r");
    if (logFp == NULL) {
      psNtcipStatus->detVOSLogCurReadPointer = -1;
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }

    // read header (there should always be a valid header)
    if (fread(&head, sizeof(head), 1, logFp) != 1) {
      psNtcipStatus->detVOSLogCurReadPointer = -1;
      *errorCode = SNMPERRORGENERALERROR;
      fclose(logFp);
      return (FALSE);
    }

    // check if log is empty
    if (head.numEntries == 0) {
      psNtcipStatus->detVOSLogCurReadPointer = -1;
      *errorCode = SNMPERRORBADVALUE; // requested value is not available
      fclose(logFp);
      return (FALSE);
    }

    // seek to and read the first entry
    filePosition = (head.firstEntry * sizeof(TYPE_VOS_log_entry)) + sizeof(head);
    if ((fseek(logFp, filePosition, SEEK_SET) != 0) || (fread(&logRecord, sizeof(logRecord), 1, logFp) != 1)) {
      psNtcipStatus->detVOSLogCurReadPointer = -1;
      *errorCode = SNMPERRORGENERALERROR;
      fclose(logFp);
      return (FALSE);
    }

    if (OID[ptrMsg->usObjectRow].oidPart[6] == 6) {
      isSeqNum = TRUE;
    } else {
      isSeqNum = FALSE;
    }

    // handle set of start position to beginning of log if requested
    if ((value == 1) || (isSeqNum && (value <= logRecord.sequenceNum)) || (!isSeqNum && (value <= logRecord.timestamp))) {
      // set start position to first entry
      ptVSMLog->u32VosLogStartSeqNum = logRecord.sequenceNum;
      ptVSMLog->u32VosLogStartTimestamp = logRecord.timestamp;
      psNtcipStatus->detVOSLogCurReadPointer = 0;
      psNtcipStatus->detVOSLogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME; // set lockout time 30 seconds forward
      fclose(logFp);
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
    }

    // seek to and read the last entry
    if (head.numEntries > 1) {
      recordNumber = (head.firstEntry + head.numEntries - 1) % MAX_VOS_LOGS;
      filePosition = (recordNumber * sizeof(TYPE_VOS_log_entry)) + sizeof(head);
      if ((fseek(logFp, filePosition, SEEK_SET) != 0) || (fread(&logRecord, sizeof(logRecord), 1, logFp) != 1)) {
        psNtcipStatus->detVOSLogCurReadPointer = -1;
        *errorCode = SNMPERRORGENERALERROR;
        fclose(logFp);
        return (FALSE);
      }
    }

    // handle set of start position to end of log if requested
    if (value == 0xFFFFFFFF) {
      // set start position to last entry
      ptVSMLog->u32VosLogStartSeqNum = logRecord.sequenceNum;
      ptVSMLog->u32VosLogStartTimestamp = logRecord.timestamp;
      psNtcipStatus->detVOSLogCurReadPointer = head.numEntries - 1;
      psNtcipStatus->detVOSLogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME; // set lockout time 30 seconds forward
      fclose(logFp);
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
    }

    // check if requested value is beyond end of log (assume that sequence numbers and timestamps never wrap)
    if ((isSeqNum && (value > logRecord.sequenceNum)) || (!isSeqNum && (value > logRecord.timestamp))) {
      psNtcipStatus->detVOSLogCurReadPointer = -1;
      *errorCode = SNMPERRORBADVALUE; // requested value is not available
      fclose(logFp);
      return (FALSE);
    }

    // If we got here then the requested start position is somewhere in the middle of the log, so we need to search
    // Skip first record since we already checked it above
    // Assume that sequence numbers and timestamps never wrap
    // Assume that all records with data are contiguous in the log file
    recordNumber = (head.firstEntry + 1) % MAX_VOS_LOGS;
    for (recordsSearched = 1; recordsSearched < head.numEntries; recordsSearched++) {
      // read next record
      filePosition = (recordNumber * sizeof(TYPE_VOS_log_entry)) + sizeof(head);
      if ((fseek(logFp, filePosition, SEEK_SET) != 0) || (fread(&logRecord, sizeof(logRecord), 1, logFp) != 1)) {
        psNtcipStatus->detVOSLogCurReadPointer = -1;
        *errorCode = SNMPERRORGENERALERROR;
        fclose(logFp);
        return (FALSE);
      }
      // check for matching sequence number or timestamp
      if ((isSeqNum && (value <= logRecord.sequenceNum)) || (!isSeqNum && (value <= logRecord.timestamp))) {
        ptVSMLog->u32VosLogStartSeqNum = logRecord.sequenceNum;
        ptVSMLog->u32VosLogStartTimestamp = logRecord.timestamp;
        psNtcipStatus->detVOSLogCurReadPointer = recordsSearched;                   // detVOSLogCurReadPointer is a zero-based index
        psNtcipStatus->detVOSLogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME; // set lockout time 30 seconds forward
        fclose(logFp);
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
      }
      // move record number to next record
      if (++recordNumber >= MAX_VOS_LOGS) {
        recordNumber = 0;
      }
    }

    // Requested value or newer was not found
    psNtcipStatus->detVOSLogCurReadPointer = -1;
    *errorCode = SNMPERRORBADVALUE; // requested value is not available
    fclose(logFp);
    return (FALSE);

  } // if (ptrMsg->boIsWriteTheValue)

  // If we got here then we are just reading the value
  if (psATCsys->upTime > psNtcipStatus->detVOSLogLockoutTime) {
    // if lock timer expired, the index is no longer valid, so return 0
    return bAppendGaugeValue(0, ptrResp, sizResp, errorCode);
  }
  if (OID[ptrMsg->usObjectRow].oidPart[6] == 6) {
    return bAppendGaugeValue(ptVSMLog->u32VosLogStartSeqNum, ptrResp, sizResp, errorCode);
  } else {
    return bAppendGaugeValue(ptVSMLog->u32VosLogStartTimestamp, ptrResp, sizResp, errorCode);
  }
}

//*******************************************************************************
//! function for VOS log clearing
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_VOSLogClearAction(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                             INT8U **ptrResp,                          //!< [inout] response buffer
                             INT16U *sizResp,                          //!< [inout] response buffer size
                             BOOLEAN __attribute__((unused)) validate, //!< not used
                             INT16U *errorCode)                        //!< [out] return error code
{
  // Variables that are specific to log type
  BOOLEAN *pClearLogRequest = &(psATCsys->clearVOSLogRequest);
  INT32U *pClearTime = &(psATCsys->clearVOStime);
  INT32U *pClearSequence = &(psATCsys->clearVOSsequence);
  INT32U lockoutTime = psNtcipStatus->detVOSLogLockoutTime;
  const int SUB_OID_SEQ_NUM = 8; // oidPart[6] value for relevant logCLearSeqNum object

  // Remainder of the code is same for MOE, VOS, SPD logs
  INT32U value = 0;
  INT16U size = 0;

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {

    // Do not allow log to be cleared if lockout timer is active
    if (psATCsys->upTime < lockoutTime) {
      *errorCode = SNMPERRORREADONLY;
      return (FALSE);
    }

    // decode and store value so it can be returned later
    if (!bDecodeGaugeValue(&ptrMsg->ucReadPointer, &value, &size, errorCode)) {
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }

    // set request to clear log (handled by thread in traffic task)
    if (OID[ptrMsg->usObjectRow].oidPart[6] == SUB_OID_SEQ_NUM) {
      *pClearSequence = value;
      *pClearTime = 0;
    } else {
      *pClearTime = value;
      *pClearSequence = 0;
    }
    *pClearLogRequest = TRUE;

    if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
      return TRUE;
    }
    return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);

  } // if (ptrMsg->boIsWriteTheValue)

  // If we got here then we are just reading the value. Return last value that was set.
  if (OID[ptrMsg->usObjectRow].oidPart[6] == SUB_OID_SEQ_NUM) {
    return bAppendGaugeValue(*pClearSequence, ptrResp, sizResp, errorCode);
  } else {
    return bAppendGaugeValue(*pClearTime, ptrResp, sizResp, errorCode);
  }
}

//*******************************************************************************
//! function for VOS Log Row read
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_VOSLogRow(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                     INT8U **ptrResp,                          //!< [inout] response buffer
                     INT16U *sizResp,                          //!< [inout] response buffer size
                     BOOLEAN __attribute__((unused)) validate, //!< not used
                     INT16U *errorCode)                        //!< [out] return error code
{
  // Variables that are specific to log type
  TYPE_log_header head;
  TYPE_VOS_log_entry logRecord;
  const char *logFileName = SNAP_DET_VOS_LOG;
  INT8U dataBlock[SIZE_VOS_ROW] = {0};

  // Variables that are generic for all log types
  long filePosition = 0;
  FILE *logFp = NULL; //!< file descriptor for log file
  INT8U *dataptr = NULL;
  INT32U tempVal = 0;
  INT8U ii = 0;
  int recordNumber = 0;
  INT16U requestedIndex = 0;

  memset(&head, 0, sizeof(head));
  memset(&logRecord, 0, sizeof(logRecord));

  if (ptrMsg->boIsWriteTheValue) {
    *errorCode = SNMPERRORREADONLY;
    return (FALSE);
  }

  // check if this is a GETNEXT request, just return zero to avoid file errors that would abort a MIB walk
  if (ptrMsg->usInPDUtype == SNMPREQUESTGETNEXT) { // Check for GET NEXT
    *errorCode = SNMPERRORNOERROR;
    memset(dataBlock, 0, sizeof(dataBlock)); // return an octet string of zeroes
    return bAppendOctet(dataBlock, ptrResp, sizResp, SIZE_VOS_ROW, errorCode);
  }

  // check to see if start position is set
  if ((psNtcipStatus->detVOSLogCurReadPointer == -1) || (psATCsys->upTime > psNtcipStatus->detVOSLogLockoutTime)) {
    // start position not set or not valid anymore
    // This is an unconventional use of BadValue, but we wanted a unique error code
    *errorCode = SNMPERRORBADVALUE;
    return (FALSE);
  } else {
    // move the lockout timer forward to prevent timeout during a sequence of gets
    psNtcipStatus->detVOSLogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME;
  }

  // open log file in SRAM (file should always exist)
  logFp = fopen(logFileName, "r");
  if (logFp == NULL) {
    *errorCode = SNMPERRORGENERALERROR;
    return (FALSE);
  }

  // read header (there should always be a valid header)
  if (fread(&head, sizeof(head), 1, logFp) != 1) {
    *errorCode = SNMPERRORGENERALERROR;
    fclose(logFp);
    return (FALSE);
  }

  // check if requested index is available in log
  requestedIndex = ptrMsg->usObjectIndex[0];
  if (requestedIndex > head.numEntries - psNtcipStatus->detVOSLogCurReadPointer) {
    *errorCode = SNMPERRORNOSUCHNAME;
    fclose(logFp);
    return (FALSE);
  }

  // calculate requested record position
  recordNumber = head.firstEntry + psNtcipStatus->detVOSLogCurReadPointer + (requestedIndex - 1);
  if (recordNumber >= MAX_VOS_LOGS) {
    recordNumber -= MAX_VOS_LOGS;
  }
  filePosition = (recordNumber * sizeof(logRecord)) + sizeof(head);

  // read record at requested position
  if ((fseek(logFp, filePosition, SEEK_SET) != 0) || (fread(&logRecord, sizeof(logRecord), 1, logFp) != 1) || (logRecord.sequenceNum == 0)) {
    *errorCode = SNMPERRORGENERALERROR;
    fclose(logFp);
    return (FALSE);
  }

  // valid record was found, serialize it into a data block according to the MIB definition of EntryData
  memset(dataBlock, 0, sizeof(dataBlock));

  tempVal = logRecord.sequenceNum;
  for (ii = 0; ii < 4; ii++) {
    dataBlock[3 - ii] = (INT8U)tempVal;
    tempVal = tempVal >> 8;
  }
  tempVal = logRecord.timestamp;
  for (ii = 0; ii < 4; ii++) {
    dataBlock[7 - ii] = (INT8U)tempVal;
    tempVal = tempVal >> 8;
  }
  tempVal = logRecord.duration;
  for (ii = 0; ii < 4; ii++) {
    dataBlock[11 - ii] = (INT8U)tempVal;
    tempVal = tempVal >> 8;
  }

  dataptr = &dataBlock[12];
  for (ii = 0; ii < MAX_LOG_DETS; ii++) {
    *dataptr++ = logRecord.det[ii].detector;
    *dataptr++ = (INT8U)(logRecord.det[ii].volume >> 8);
    *dataptr++ = (INT8U)(logRecord.det[ii].volume);
    *dataptr++ = logRecord.det[ii].occupancy;
    *dataptr++ = (INT8U)(logRecord.det[ii].speed >> 8);
    *dataptr++ = (INT8U)(logRecord.det[ii].speed);
  }

  // success
  *errorCode = SNMPERRORNOERROR;
  fclose(logFp);
  return bAppendOctet(dataBlock, ptrResp, sizResp, SIZE_VOS_ROW, errorCode);
}

//*******************************************************************************
//! function for speed trap entries
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN
fn_speedTrapEntries(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                    INT8U **ptrResp,        //!< [inout] response buffer
                    INT16U *sizResp,        //!< [inout] response buffer size
                    BOOLEAN validate,       //!< only perform dry-run write if set
                    INT16U *errorCode)      //!< [out] return error code
{
  INT16U newVal = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt2(&ptrMsg->ucReadPointer, &newVal, errorCode)) {
      if ((newVal < OID[ptrMsg->usObjectRow].oidMin) || (newVal > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      if ((OID[ptrMsg->usObjectRow].oidPart[6] >= 18) && (OID[ptrMsg->usObjectRow].oidPart[6] <= 20)) {
        // mcAtcSpeedTrapSeqNum, mcAtcSpeedTrapTimestamp, mcAtcSpeedTrapDuration
        *errorCode = SNMPERRORREADONLY;
        return FALSE;
      }
      switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
        case 2:                                                                                         // mcAtcSpeedTrapDet1
          if (ptrMsg->ptNtcipParameters->mcAtcSpeedTrap[ptrMsg->usObjectIndex[0] - 1].det1 != newVal) { // check if data changed or setting the same value again
            psATCsys->clearSPDtime = 0xFFFFFFFF;                                                        // set to clear all entries
            psATCsys->clearSPDsequence = 0;
            psATCsys->clearSPDLogRequest = TRUE; // set flag to clear log
          }
          ptrMsg->ptNtcipParameters->mcAtcSpeedTrap[ptrMsg->usObjectIndex[0] - 1].det1 = newVal;
          if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
            return TRUE;
          }
          return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcSpeedTrap[ptrMsg->usObjectIndex[0] - 1].det1, ptrResp, sizResp, errorCode);
        case 3:                                                                                         // mcAtcSpeedTrapDet2
          if (ptrMsg->ptNtcipParameters->mcAtcSpeedTrap[ptrMsg->usObjectIndex[0] - 1].det2 != newVal) { // check if data changed or setting the same value again
            psATCsys->clearSPDtime = 0xFFFFFFFF;                                                        // set to clear all entries
            psATCsys->clearSPDsequence = 0;
            psATCsys->clearSPDLogRequest = TRUE; // set flag to clear log
          }
          ptrMsg->ptNtcipParameters->mcAtcSpeedTrap[ptrMsg->usObjectIndex[0] - 1].det2 = newVal;
          if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
            return TRUE;
          }
          return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcSpeedTrap[ptrMsg->usObjectIndex[0] - 1].det2, ptrResp, sizResp, errorCode);
        case 4:                                                                                             // mcAtcSpeedTrapDistance
          if (ptrMsg->ptNtcipParameters->mcAtcSpeedTrap[ptrMsg->usObjectIndex[0] - 1].distance != newVal) { // check if data changed or setting the same value again
            psATCsys->clearSPDtime = 0xFFFFFFFF;                                                            // set to clear all entries
            psATCsys->clearSPDsequence = 0;
            psATCsys->clearSPDLogRequest = TRUE; // set flag to clear log
          }
          ptrMsg->ptNtcipParameters->mcAtcSpeedTrap[ptrMsg->usObjectIndex[0] - 1].distance = newVal;
          if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
            return TRUE;
          }
          return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcSpeedTrap[ptrMsg->usObjectIndex[0] - 1].distance, ptrResp, sizResp, errorCode);
        case 5: // mcAtcSpeedTrapAvgSpeed
        case 6: // mcAtcSpeedTrapBinCounts
          *errorCode = SNMPERRORREADONLY;
          return FALSE;
        default:
          *errorCode = SNMPERRORNOSUCHNAME;
          return (FALSE);
      }
    } else {
      return (FALSE); // errorCode set by bDecodeUInt2
    }
  }

  if (OID[ptrMsg->usObjectRow].oidPart[6] == 3) {
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 2: // mcAtcSpeedTrapDet1
        return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcSpeedTrap[ptrMsg->usObjectIndex[0] - 1].det1, ptrResp, sizResp, errorCode);
      case 3: // mcAtcSpeedTrapDet2
        return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcSpeedTrap[ptrMsg->usObjectIndex[0] - 1].det2, ptrResp, sizResp, errorCode);
      case 4: // mcAtcSpeedTrapDistance
        return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcSpeedTrap[ptrMsg->usObjectIndex[0] - 1].distance, ptrResp, sizResp, errorCode);
      case 5: // mcAtcSpeedTrapAvgSpeed
        return bAppendUInt(psTrafficOut->spdLogEntry.trap[ptrMsg->usObjectIndex[0] - 1].speed, ptrResp, sizResp, errorCode);
      case 6: // mcAtcSpeedTrapBinCounts
        return bAppendOctet(psTrafficOut->spdLogEntry.trap[ptrMsg->usObjectIndex[0] - 1].speedbins, ptrResp, sizResp, MAX_SPEED_BINS, errorCode);
      default:
        break;
    }
  } else {
    switch (OID[ptrMsg->usObjectRow].oidPart[6]) {
      case 18: // mcAtcSpeedTrapSeqNum
        return bAppendGaugeValue(psTrafficOut->spdLogEntry.sequenceNum, ptrResp, sizResp, errorCode);
      case 19: // mcAtcSpeedTrapTimestamp
        return bAppendGaugeValue(psTrafficOut->spdLogEntry.timestamp, ptrResp, sizResp, errorCode);
      case 20: // mcAtcSpeedTrapDuration
        return bAppendGaugeValue(psTrafficOut->spdLogEntry.duration, ptrResp, sizResp, errorCode);
      default:
        break;
    }
  }
  *errorCode = SNMPERRORNOSUCHNAME;
  return (FALSE);
}

//*******************************************************************************
//! function for speed trap bin configuration
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_speedBinRange(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                         INT8U **ptrResp,        //!< [inout] response buffer
                         INT16U *sizResp,        //!< [inout] response buffer size
                         BOOLEAN validate,       //!< only perform dry-run write if set
                         INT16U *errorCode)      //!< [out] return error code
{
  INT8U newVal = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &newVal, errorCode)) {
      if ((newVal < OID[ptrMsg->usObjectRow].oidMin) || (newVal > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }

      if (ptrMsg->ptNtcipParameters->mcAtcSpeedBinRange[ptrMsg->usObjectIndex[0] - 1] != newVal) { // check if data changed or setting the same value again
        psATCsys->clearSPDtime = 0xFFFFFFFF;                                                       // set to clear all entries
        psATCsys->clearSPDsequence = 0;
        psATCsys->clearSPDLogRequest = TRUE; // set flag to clear log
      }
      ptrMsg->ptNtcipParameters->mcAtcSpeedBinRange[ptrMsg->usObjectIndex[0] - 1] = newVal;
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcSpeedBinRange[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    } else {
      return (FALSE); // errorCode set by bDecodeUInt1
    }
  }
  return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcSpeedBinRange[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
} // end fn_speedBinRange()

//*******************************************************************************
//! function for Speed log number of entries
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_speedLogNumEntries(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                              INT8U **ptrResp,                          //!< [inout] response buffer
                              INT16U *sizResp,                          //!< [inout] response buffer size
                              BOOLEAN __attribute__((unused)) validate, //!< not used
                              INT16U *errorCode)                        //!< [out] return error code
{
  // Variables that are specific to log type
  TYPE_log_header head;
  const char *logFileName = SNAP_DET_SPD_LOG;

  // Variables that are generic for all log types
  FILE *logFp = NULL;
  int numEntries = 0;

  memset(&head, 0, sizeof(head));

  if (ptrMsg->boIsWriteTheValue) {
    *errorCode = SNMPERRORREADONLY;
    return (FALSE);
  }

  // check if this is a GETNEXT request, just return zero to avoid file errors that would abort a MIB walk
  if (ptrMsg->usInPDUtype == SNMPREQUESTGETNEXT) { // Check for GET NEXT
    *errorCode = SNMPERRORNOERROR;
    return bAppendUInt(0, ptrResp, sizResp, errorCode); // return zero
  }

  // check to see if start position is set
  if ((psNtcipStatus->speedTrapLogCurReadPointer == -1) || (psATCsys->upTime > psNtcipStatus->speedTrapLogLockoutTime)) {
    // start position not set or not valid anymore
    // This is an unconventional use of BadValue, but we wanted a unique error code
    *errorCode = SNMPERRORBADVALUE;
    return (FALSE);
  }

  // open log file in SRAM (file should always exist)
  logFp = fopen(logFileName, "r");
  if (logFp == NULL) {
    *errorCode = SNMPERRORGENERALERROR;
    return (FALSE);
  }

  // read header (there should always be a valid header)
  if (fread(&head, sizeof(head), 1, logFp) != 1) {
    *errorCode = SNMPERRORGENERALERROR;
    fclose(logFp);
    return (FALSE);
  }
  fclose(logFp);

  numEntries = head.numEntries - psNtcipStatus->speedTrapLogCurReadPointer;
  if (numEntries < 0) {
    *errorCode = SNMPERRORGENERALERROR;
    return FALSE;
  }

  *errorCode = SNMPERRORNOERROR;
  return bAppendUInt((INT32U)numEntries, ptrResp, sizResp, errorCode);
} // end fn_SpeedLogNumEntries()

//*******************************************************************************
//! function for Speed log reading
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_speedLogReadAction(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                              INT8U **ptrResp,                          //!< [inout] response buffer
                              INT16U *sizResp,                          //!< [inout] response buffer size
                              BOOLEAN __attribute__((unused)) validate, //!< not used
                              INT16U *errorCode)                        //!< [out] return error code
{

  // Variables that are specific to log type
  TYPE_log_header head;
  TYPE_SPD_log_entry logRecord;
  const char *logFileName = SNAP_DET_SPD_LOG;

  // Variables that are generic for all log types
  long filePosition = 0;
  FILE *logFp = NULL; //!< file descriptor for log
  INT32U value = 0;
  BOOLEAN isSeqNum = FALSE; // true if requested value is sequence number, else it is a timestamp
  INT16U size = 0;
  int recordNumber = 0;
  int recordsSearched = 0;

  memset(&head, 0, sizeof(head));
  memset(&logRecord, 0, sizeof(logRecord));

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {
    if (!bDecodeGaugeValue(&ptrMsg->ucReadPointer, &value, &size, errorCode)) {
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }
    if (value == 0) {
      // Clear start position
      psNtcipStatus->speedTrapLogCurReadPointer = -1;
      psNtcipStatus->speedTrapLogLockoutTime = 0;
      ptVSMLog->u32SpeedLogStartSeqNum = 0;
      ptVSMLog->u32SpeedLogStartTimestamp = 0;
      // delete the snapshot of the log if one exists (ignore output and errors)
      if (system("rm -f " SNAP_DET_SPD_LOG " >/dev/null 2>&1") == -1) {
        vMcSysLog(LOG_ERR, "Failed to remove temp directory: %s", SNAP_DET_SPD_LOG);
      }
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
    } else if (psATCsys->upTime < psNtcipStatus->speedTrapLogLockoutTime) {
      // Don't allow start position to be changed if lockout timer is active
      *errorCode = SNMPERRORREADONLY;
      return (FALSE);
    }

    // take a snapshot of the log
    remove(SNAP_DET_SPD_LOG); // delete the snapshot of the log if one exists (ignore errors)
    // Copy the file
    pthread_mutex_lock(&(psATCsys->workingSPDLogMutex));
    if (!(bCopyFile((CHAR *)(WFN_DET_SPD_LOG), (CHAR *)(SNAP_DET_SPD_LOG)))) { //, sizeof(logRecord)))) {
      pthread_mutex_unlock(&(psATCsys->workingSPDLogMutex));
      psNtcipStatus->speedTrapLogCurReadPointer = -1;
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }
    psNtcipStatus->speedTrapLogSnapshotTaken = TRUE;
    pthread_mutex_unlock(&(psATCsys->workingSPDLogMutex));

    // open log file in SRAM (file should always exist)
    logFp = fopen(logFileName, "r");
    if (logFp == NULL) {
      psNtcipStatus->speedTrapLogCurReadPointer = -1;
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }

    // read header (there should always be a valid header)
    if (fread(&head, sizeof(head), 1, logFp) != 1) {
      psNtcipStatus->speedTrapLogCurReadPointer = -1;
      *errorCode = SNMPERRORGENERALERROR;
      fclose(logFp);
      return (FALSE);
    }

    // check if log is empty
    if (head.numEntries == 0) {
      psNtcipStatus->speedTrapLogCurReadPointer = -1;
      *errorCode = SNMPERRORBADVALUE; // requested value is not available
      fclose(logFp);
      return (FALSE);
    }

    // seek to and read the first entry
    filePosition = (head.firstEntry * sizeof(TYPE_SPD_log_entry)) + sizeof(head);
    if ((fseek(logFp, filePosition, SEEK_SET) != 0) || (fread(&logRecord, sizeof(logRecord), 1, logFp) != 1)) {
      psNtcipStatus->speedTrapLogCurReadPointer = -1;
      *errorCode = SNMPERRORGENERALERROR;
      fclose(logFp);
      return (FALSE);
    }

    if (OID[ptrMsg->usObjectRow].oidPart[6] == 11) {
      isSeqNum = TRUE;
    } else {
      isSeqNum = FALSE;
    }

    // handle set of start position to beginning of log if requested
    if ((value == 1) || (isSeqNum && (value <= logRecord.sequenceNum)) || (!isSeqNum && (value <= logRecord.timestamp))) {
      // set start position to first entry
      ptVSMLog->u32SpeedLogStartSeqNum = logRecord.sequenceNum;
      ptVSMLog->u32SpeedLogStartTimestamp = logRecord.timestamp;
      psNtcipStatus->speedTrapLogCurReadPointer = 0;
      psNtcipStatus->speedTrapLogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME; // set lockout time 30 seconds forward
      fclose(logFp);
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
    }

    // seek to and read the last entry
    if (head.numEntries > 1) {
      recordNumber = (head.firstEntry + head.numEntries - 1) % MAX_SPD_LOGS;
      filePosition = (recordNumber * sizeof(TYPE_SPD_log_entry)) + sizeof(head);
      if ((fseek(logFp, filePosition, SEEK_SET) != 0) || (fread(&logRecord, sizeof(logRecord), 1, logFp) != 1)) {
        psNtcipStatus->speedTrapLogCurReadPointer = -1;
        *errorCode = SNMPERRORGENERALERROR;
        fclose(logFp);
        return (FALSE);
      }
    }

    // handle set of start position to end of log if requested
    if (value == 0xFFFFFFFF) {
      // set start position to last entry
      ptVSMLog->u32SpeedLogStartSeqNum = logRecord.sequenceNum;
      ptVSMLog->u32SpeedLogStartTimestamp = logRecord.timestamp;
      psNtcipStatus->speedTrapLogCurReadPointer = head.numEntries - 1;
      psNtcipStatus->speedTrapLogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME; // set lockout time 30 seconds forward
      fclose(logFp);
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
    }

    // check if requested value is beyond end of log (assume that sequence numbers and timestamps never wrap)
    if ((isSeqNum && (value > logRecord.sequenceNum)) || (!isSeqNum && (value > logRecord.timestamp))) {
      psNtcipStatus->speedTrapLogCurReadPointer = -1;
      *errorCode = SNMPERRORBADVALUE; // requested value is not available
      fclose(logFp);
      return (FALSE);
    }

    // If we got here then the requested start position is somewhere in the middle of the log, so we need to search
    // Skip first record since we already checked it above
    // Assume that sequence numbers and timestamps never wrap
    // Assume that all records with data are contiguous in the log file
    recordNumber = (head.firstEntry + 1) % MAX_SPD_LOGS;
    for (recordsSearched = 1; recordsSearched < head.numEntries; recordsSearched++) {
      // read next record
      filePosition = (recordNumber * sizeof(TYPE_SPD_log_entry)) + sizeof(head);
      if ((fseek(logFp, filePosition, SEEK_SET) != 0) || (fread(&logRecord, sizeof(logRecord), 1, logFp) != 1)) {
        psNtcipStatus->speedTrapLogCurReadPointer = -1;
        *errorCode = SNMPERRORGENERALERROR;
        fclose(logFp);
        return (FALSE);
      }
      // check for matching sequence number or timestamp
      if ((isSeqNum && (value <= logRecord.sequenceNum)) || (!isSeqNum && (value <= logRecord.timestamp))) {
        ptVSMLog->u32SpeedLogStartSeqNum = logRecord.sequenceNum;
        ptVSMLog->u32SpeedLogStartTimestamp = logRecord.timestamp;
        psNtcipStatus->speedTrapLogCurReadPointer = recordsSearched;                   // speedTrapLogCurReadPointer is a zero-based index
        psNtcipStatus->speedTrapLogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME; // set lockout time 30 seconds forward
        fclose(logFp);
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
      }
      // move record number to next record
      if (++recordNumber >= MAX_SPD_LOGS) {
        recordNumber = 0;
      }
    }

    // Requested value or newer was not found
    psNtcipStatus->speedTrapLogCurReadPointer = -1;
    *errorCode = SNMPERRORBADVALUE; // requested value is not available
    fclose(logFp);
    return (FALSE);

  } // if (ptrMsg->boIsWriteTheValue)

  // If we got here then we are just reading the value
  if (psATCsys->upTime > psNtcipStatus->speedTrapLogLockoutTime) {
    // if lock timer expired, the index is no longer valid, so return 0
    return bAppendGaugeValue(0, ptrResp, sizResp, errorCode);
  }
  if (OID[ptrMsg->usObjectRow].oidPart[6] == 11) {
    return bAppendGaugeValue(ptVSMLog->u32SpeedLogStartSeqNum, ptrResp, sizResp, errorCode);
  } else {
    return bAppendGaugeValue(ptVSMLog->u32SpeedLogStartTimestamp, ptrResp, sizResp, errorCode);
  }
}

//*******************************************************************************
//! function for Speed log clearing
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_speedLogClearAction(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                               INT8U **ptrResp,                          //!< [inout] response buffer
                               INT16U *sizResp,                          //!< [inout] response buffer size
                               BOOLEAN __attribute__((unused)) validate, //!< not used
                               INT16U *errorCode)                        //!< [out] return error code
{
  // Variables that are specific to log type
  BOOLEAN *pClearLogRequest = &(psATCsys->clearSPDLogRequest);
  INT32U *pClearTime = &(psATCsys->clearSPDtime);
  INT32U *pClearSequence = &(psATCsys->clearSPDsequence);
  INT32U lockoutTime = psNtcipStatus->speedTrapLogLockoutTime;
  const int SUB_OID_SEQ_NUM = 13; // oidPart[6] value for relevant logCLearSeqNum object

  // Remainder of the code is same for MOE, VOS, SPD logs
  INT32U value = 0;
  INT16U size = 0;

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {

    // Do not allow log to be cleared if lockout timer is active
    if (psATCsys->upTime < lockoutTime) {
      *errorCode = SNMPERRORREADONLY;
      return (FALSE);
    }

    // decode and store value so it can be returned later
    if (!bDecodeGaugeValue(&ptrMsg->ucReadPointer, &value, &size, errorCode)) {
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }

    // set request to clear log (handled by thread in traffic task)
    if (OID[ptrMsg->usObjectRow].oidPart[6] == SUB_OID_SEQ_NUM) {
      *pClearSequence = value;
      *pClearTime = 0;
    } else {
      *pClearTime = value;
      *pClearSequence = 0;
    }
    *pClearLogRequest = TRUE;

    if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
      return TRUE;
    }
    return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);

  } // if (ptrMsg->boIsWriteTheValue)

  // If we got here then we are just reading the value. Return last value that was set.
  if (OID[ptrMsg->usObjectRow].oidPart[6] == SUB_OID_SEQ_NUM) {
    return bAppendGaugeValue(*pClearSequence, ptrResp, sizResp, errorCode);
  } else {
    return bAppendGaugeValue(*pClearTime, ptrResp, sizResp, errorCode);
  }
}

//*******************************************************************************
//! function for Speed Log Row read
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_speedLogRow(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                       INT8U **ptrResp,                          //!< [inout] response buffer
                       INT16U *sizResp,                          //!< [inout] response buffer size
                       BOOLEAN __attribute__((unused)) validate, //!< not used
                       INT16U *errorCode)                        //!< [out] return error code
{
  // Variables that are specific to log type
  TYPE_log_header head;
  TYPE_SPD_log_entry logRecord;
  const char *logFileName = SNAP_DET_SPD_LOG;
  INT8U dataBlock[SIZE_SPEED_ROW] = {0};

  // Variables that are generic for all log types
  long filePosition = 0;
  FILE *logFp = NULL; //!< file descriptor for log file
  INT8U *dataptr = NULL;
  INT32U tempVal = 0;
  INT8U ii = 0, jj = 0;
  int recordNumber = 0;
  INT16U requestedIndex = 0;

  memset(&head, 0, sizeof(head));
  memset(&logRecord, 0, sizeof(logRecord));

  if (ptrMsg->boIsWriteTheValue) {
    *errorCode = SNMPERRORREADONLY;
    return (FALSE);
  }

  // check if this is a GETNEXT request, just return zero to avoid file errors that would abort a MIB walk
  if (ptrMsg->usInPDUtype == SNMPREQUESTGETNEXT) { // Check for GET NEXT
    *errorCode = SNMPERRORNOERROR;
    memset(dataBlock, 0, sizeof(dataBlock)); // return an octet string of zeroes
    return bAppendOctet(dataBlock, ptrResp, sizResp, SIZE_SPEED_ROW, errorCode);
  }

  // check to see if start position is set
  if ((psNtcipStatus->speedTrapLogCurReadPointer == -1) || (psATCsys->upTime > psNtcipStatus->speedTrapLogLockoutTime)) {
    // start position not set or not valid anymore
    // This is an unconventional use of BadValue, but we wanted a unique error code
    *errorCode = SNMPERRORBADVALUE;
    return (FALSE);
  } else {
    // move the lockout timer forward to prevent timeout during a sequence of gets
    psNtcipStatus->speedTrapLogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME;
  }

  // open log file in SRAM (file should always exist)
  logFp = fopen(logFileName, "r");
  if (logFp == NULL) {
    *errorCode = SNMPERRORGENERALERROR;
    return (FALSE);
  }

  // read header (there should always be a valid header)
  if (fread(&head, sizeof(head), 1, logFp) != 1) {
    *errorCode = SNMPERRORGENERALERROR;
    fclose(logFp);
    return (FALSE);
  }

  // check if requested index is available in log
  requestedIndex = ptrMsg->usObjectIndex[0];
  if (requestedIndex > head.numEntries - psNtcipStatus->speedTrapLogCurReadPointer) {
    fclose(logFp);
    *errorCode = SNMPERRORNOSUCHNAME;
    return (FALSE);
  }

  // calculate requested record position
  recordNumber = head.firstEntry + psNtcipStatus->speedTrapLogCurReadPointer + (requestedIndex - 1);
  if (recordNumber >= MAX_SPD_LOGS) {
    recordNumber -= MAX_SPD_LOGS;
  }
  filePosition = (recordNumber * sizeof(logRecord)) + sizeof(head);

  // read record at requested position
  if ((fseek(logFp, filePosition, SEEK_SET) != 0) || (fread(&logRecord, sizeof(logRecord), 1, logFp) != 1) || (logRecord.sequenceNum == 0)) {
    *errorCode = SNMPERRORGENERALERROR;
    fclose(logFp);
    return (FALSE);
  }

  // valid record was found, serialize it into a data block according to the MIB definition of EntryData
  memset(dataBlock, 0, sizeof(dataBlock));

  tempVal = logRecord.sequenceNum;
  for (ii = 0; ii < 4; ii++) {
    dataBlock[3 - ii] = (INT8U)tempVal;
    tempVal = tempVal >> 8;
  }
  tempVal = logRecord.timestamp;
  for (ii = 0; ii < 4; ii++) {
    dataBlock[7 - ii] = (INT8U)tempVal;
    tempVal = tempVal >> 8;
  }
  tempVal = logRecord.duration;
  for (ii = 0; ii < 4; ii++) {
    dataBlock[11 - ii] = (INT8U)tempVal;
    tempVal = tempVal >> 8;
  }

  dataptr = &dataBlock[12];
  for (ii = 0; ii < MAX_SPEED_TRAPS; ii++) {
    *dataptr++ = (INT8U)(logRecord.trap[ii].speed << 8);
    *dataptr++ = (INT8U)logRecord.trap[ii].speed;
    for (jj = 0; jj < MAX_SPEED_BINS; jj++) {
      *dataptr++ = logRecord.trap[ii].speedbins[jj];
    }
  }

  // success
  *errorCode = SNMPERRORNOERROR;
  fclose(logFp);
  return bAppendOctet(dataBlock, ptrResp, sizResp, SIZE_SPEED_ROW, errorCode);
}

//*******************************************************************************
//! function for MOE log number of entries
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_cycMOELogNumEntries(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                               INT8U **ptrResp,                          //!< [inout] response buffer
                               INT16U *sizResp,                          //!< [inout] response buffer size
                               BOOLEAN __attribute__((unused)) validate, //!< not used
                               INT16U *errorCode)                        //!< [out] return error code
{
  // Variables that are specific to log type
  TYPE_log_header head;
  const char *logFileName = SNAP_CYC_MOE_LOG;

  // Variables that are generic for all log types
  FILE *logFp = NULL;
  int numEntries = 0;

  memset(&head, 0, sizeof(head));

  if (ptrMsg->boIsWriteTheValue) {
    *errorCode = SNMPERRORREADONLY;
    return (FALSE);
  }

  // check if this is a GETNEXT request, just return zero to avoid file errors that would abort a MIB walk
  if (ptrMsg->usInPDUtype == SNMPREQUESTGETNEXT) { // Check for GET NEXT
    *errorCode = SNMPERRORNOERROR;
    return bAppendUInt(0, ptrResp, sizResp, errorCode); // return zero
  }

  // check to see if start position is set
  if ((psNtcipStatus->cycleMOELogCurReadPointer == -1) || (psATCsys->upTime > psNtcipStatus->cycleMOELogLockoutTime)) {
    // start position not set or not valid anymore
    // This is an unconventional use of BadValue, but we wanted a unique error code
    *errorCode = SNMPERRORBADVALUE;
    return (FALSE);
  }

  // open log file (file should always exist)
  logFp = fopen(logFileName, "r");
  if (logFp == NULL) {
    *errorCode = SNMPERRORGENERALERROR;
    return (FALSE);
  }

  // read header (there should always be a valid header)
  if (fread(&head, sizeof(head), 1, logFp) != 1) {
    *errorCode = SNMPERRORGENERALERROR;
    fclose(logFp);
    return (FALSE);
  }
  fclose(logFp);

  numEntries = head.numEntries - psNtcipStatus->cycleMOELogCurReadPointer;
  if (numEntries < 0) {
    *errorCode = SNMPERRORGENERALERROR;
    return FALSE;
  }

  *errorCode = SNMPERRORNOERROR;
  return bAppendUInt((INT32U)numEntries, ptrResp, sizResp, errorCode);
} // end fn_cycMOELogNumEntries()

//*******************************************************************************
//! function for MOE log reading
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_cycMOELogReadAction(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                               INT8U **ptrResp,                          //!< [inout] response buffer
                               INT16U *sizResp,                          //!< [inout] response buffer size
                               BOOLEAN __attribute__((unused)) validate, //!< not used
                               INT16U *errorCode)                        //!< [out] return error code
{
  // Variables that are specific to log type
  TYPE_log_header head;
  TYPE_MOE_log_entry logRecord;
  const char *logFileName = WFN_CYC_MOE_LOG;

  // Variables that are generic for all log types
  long filePosition = 0;
  FILE *logFp = NULL; //!< file descriptor for MOE log
  INT32U value = 0;
  BOOLEAN isSeqNum = FALSE; // true if requested value is sequence number, else it is a timestamp
  INT16U size = 0;
  int recordNumber = 0;
  int recordsSearched = 0;

  memset(&head, 0, sizeof(head));
  memset(&logRecord, 0, sizeof(logRecord));

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {

    if (!bDecodeGaugeValue(&ptrMsg->ucReadPointer, &value, &size, errorCode)) {
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }

    if (value == 0) {
      // Clear start position
      psNtcipStatus->cycleMOELogCurReadPointer = -1;
      psNtcipStatus->cycleMOELogLockoutTime = 0;
      ptVSMLog->u32MoeLogStartSeqNum = 0;
      ptVSMLog->u32MoeLogStartTimestamp = 0;
      // delete the snapshot of the log if one exists (ignore output and errors)
      if (system("rm -f " SNAP_CYC_MOE_LOG " >/dev/null 2>&1") == -1) {
        vMcSysLog(LOG_ERR, "Failed to remove temp directory: %s", SNAP_CYC_MOE_LOG);
      }
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
    } else if (psATCsys->upTime <= psNtcipStatus->cycleMOELogLockoutTime) {
      // Don't allow start position to be changed if lockout timer is active
      *errorCode = SNMPERRORREADONLY;
      return (FALSE);
    }

    // take a snapshot of the log
    remove(SNAP_CYC_MOE_LOG); // delete the snapshot of the log if one exists (ignore errors)
    // Copy the file
    pthread_mutex_lock(&(psATCsys->workingMOELogMutex));
    if (!(bCopyFile((CHAR *)(WFN_CYC_MOE_LOG), (CHAR *)(SNAP_CYC_MOE_LOG)))) { //, sizeof(logRecord)))) {
      pthread_mutex_unlock(&(psATCsys->workingMOELogMutex));
      psNtcipStatus->cycleMOELogCurReadPointer = -1;
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }
    psNtcipStatus->cycleMOELogSnapshotTaken = TRUE;
    pthread_mutex_unlock(&(psATCsys->workingMOELogMutex));

    // open log file in SRAM (file should always exist)
    logFp = fopen(logFileName, "r");
    if (logFp == NULL) {
      psNtcipStatus->cycleMOELogCurReadPointer = -1;
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }

    // read header (there should always be a valid header)
    if (fread(&head, sizeof(head), 1, logFp) != 1) {
      psNtcipStatus->cycleMOELogCurReadPointer = -1;
      *errorCode = SNMPERRORGENERALERROR;
      fclose(logFp);
      return (FALSE);
    }

    // check if log is empty
    if (head.numEntries == 0) {
      psNtcipStatus->cycleMOELogCurReadPointer = -1;
      *errorCode = SNMPERRORBADVALUE; // requested value is not available
      fclose(logFp);
      return (FALSE);
    }

    // seek to and read the first entry
    filePosition = (head.firstEntry * sizeof(TYPE_MOE_log_entry)) + sizeof(head);
    if ((fseek(logFp, filePosition, SEEK_SET) != 0) || (fread(&logRecord, sizeof(logRecord), 1, logFp) != 1)) {
      psNtcipStatus->cycleMOELogCurReadPointer = -1;
      *errorCode = SNMPERRORGENERALERROR;
      fclose(logFp);
      return (FALSE);
    }

    if (OID[ptrMsg->usObjectRow].oidPart[6] == 4) {
      isSeqNum = TRUE;
    } else {
      isSeqNum = FALSE;
    }

    // handle set of start position to beginning of log if requested
    if ((value == 1) || (isSeqNum && (value <= logRecord.sequenceNum)) || (!isSeqNum && (value <= logRecord.timestamp))) {
      // set start position to first entry
      ptVSMLog->u32MoeLogStartSeqNum = logRecord.sequenceNum;
      ptVSMLog->u32MoeLogStartTimestamp = logRecord.timestamp;
      psNtcipStatus->cycleMOELogCurReadPointer = 0;
      psNtcipStatus->cycleMOELogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME;
      fclose(logFp);
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
    }

    // seek to and read the last entry
    if (head.numEntries > 1) {
      recordNumber = (head.firstEntry + head.numEntries - 1) % MAX_MOE_LOGS;
      filePosition = (recordNumber * sizeof(TYPE_MOE_log_entry)) + sizeof(head);
      if ((fseek(logFp, filePosition, SEEK_SET) != 0) || (fread(&logRecord, sizeof(logRecord), 1, logFp) != 1)) {
        psNtcipStatus->cycleMOELogCurReadPointer = -1;
        *errorCode = SNMPERRORGENERALERROR;
        fclose(logFp);
        return (FALSE);
      }
    }

    // handle set of start position to end of log if requested
    if (value == 0xFFFFFFFF) {
      // set start position to last entry
      ptVSMLog->u32MoeLogStartSeqNum = logRecord.sequenceNum;
      ptVSMLog->u32MoeLogStartTimestamp = logRecord.timestamp;
      psNtcipStatus->cycleMOELogCurReadPointer = head.numEntries - 1;
      psNtcipStatus->cycleMOELogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME;
      fclose(logFp);
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
    }

    // check if requested value is beyond end of log (assume that sequence numbers and timestamps never wrap)
    if ((isSeqNum && (value > logRecord.sequenceNum)) || (!isSeqNum && (value > logRecord.timestamp))) {
      psNtcipStatus->cycleMOELogCurReadPointer = -1;
      *errorCode = SNMPERRORBADVALUE; // requested value is not available
      fclose(logFp);
      return (FALSE);
    }

    // If we got here then the requested start position is somewhere in the middle of the log, so we need to search
    // Skip first record since we already checked it above
    // Assume that sequence numbers and timestamps never wrap
    // Assume that all records with data are contiguous in the log file
    recordNumber = (head.firstEntry + 1) % MAX_MOE_LOGS;
    for (recordsSearched = 1; recordsSearched < head.numEntries; recordsSearched++) {
      // read next record
      filePosition = (recordNumber * sizeof(TYPE_MOE_log_entry)) + sizeof(head);
      if ((fseek(logFp, filePosition, SEEK_SET) != 0) || (fread(&logRecord, sizeof(logRecord), 1, logFp) != 1)) {
        psNtcipStatus->cycleMOELogCurReadPointer = -1;
        *errorCode = SNMPERRORGENERALERROR;
        fclose(logFp);
        return (FALSE);
      }
      // check for matching sequence number or timestamp
      if ((isSeqNum && (value <= logRecord.sequenceNum)) || (!isSeqNum && (value <= logRecord.timestamp))) {
        ptVSMLog->u32MoeLogStartSeqNum = logRecord.sequenceNum;
        ptVSMLog->u32MoeLogStartTimestamp = logRecord.timestamp;
        psNtcipStatus->cycleMOELogCurReadPointer = recordsSearched; // CurReadPointer is a zero-based index
        psNtcipStatus->cycleMOELogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME;
        fclose(logFp);
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
      }
      // move record number to next record
      if (++recordNumber >= MAX_MOE_LOGS) {
        recordNumber = 0;
      }
    }

    // Requested value or newer was not found
    psNtcipStatus->cycleMOELogCurReadPointer = -1;
    *errorCode = SNMPERRORBADVALUE; // requested value is not available
    fclose(logFp);
    return (FALSE);

  } // if (ptrMsg->boIsWriteTheValue)

  // If we got here then we are just reading the value
  if (psATCsys->upTime > psNtcipStatus->cycleMOELogLockoutTime) {
    // if lock timer expired, the index is no longer valid, so return 0
    return bAppendGaugeValue(0, ptrResp, sizResp, errorCode);
  }
  if (OID[ptrMsg->usObjectRow].oidPart[6] == 4) {
    return bAppendGaugeValue(ptVSMLog->u32MoeLogStartSeqNum, ptrResp, sizResp, errorCode);
  } else {
    return bAppendGaugeValue(ptVSMLog->u32MoeLogStartTimestamp, ptrResp, sizResp, errorCode);
  }
} // end fn_cycMOELogReadAction

//*******************************************************************************
//! function for MOE log clearing
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_cycMOELogClearAction(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                                INT8U **ptrResp,                          //!< [inout] response buffer
                                INT16U *sizResp,                          //!< [inout] response buffer size
                                BOOLEAN __attribute__((unused)) validate, //!< not used
                                INT16U *errorCode)                        //!< [out] return error code
{
  // Variables that are specific to log type
  BOOLEAN *pClearLogRequest = &(psATCsys->clearMOELogRequest);
  INT32U *pClearTime = &(psATCsys->clearMOEtime);
  INT32U *pClearSequence = &(psATCsys->clearMOEsequence);
  INT32U lockoutTime = psNtcipStatus->cycleMOELogLockoutTime;
  const int SUB_OID_SEQ_NUM = 6; // oidPart[6] value for relevant logCLearSeqNum object

  // Remainder of the code is same for MOE, VOS, SPD logs
  INT32U value = 0;
  INT16U size = 0;

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {

    // Do not allow log to be cleared if lockout timer is active
    if (psATCsys->upTime < lockoutTime) {
      *errorCode = SNMPERRORREADONLY;
      return (FALSE);
    }

    // decode and store value so it can be returned later
    if (!bDecodeGaugeValue(&ptrMsg->ucReadPointer, &value, &size, errorCode)) {
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }

    // set request to clear log (handled by thread in traffic task)
    if (OID[ptrMsg->usObjectRow].oidPart[6] == SUB_OID_SEQ_NUM) {
      *pClearSequence = value;
      *pClearTime = 0;
    } else {
      *pClearTime = value;
      *pClearSequence = 0;
    }
    *pClearLogRequest = TRUE;

    if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
      return TRUE;
    }
    return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);

  } // if (ptrMsg->boIsWriteTheValue)

  // If we got here then we are just reading the value. Return last value that was set.
  if (OID[ptrMsg->usObjectRow].oidPart[6] == SUB_OID_SEQ_NUM) {
    return bAppendGaugeValue(*pClearSequence, ptrResp, sizResp, errorCode);
  } else {
    return bAppendGaugeValue(*pClearTime, ptrResp, sizResp, errorCode);
  }
}

//*******************************************************************************
//! function for MOE Log Row read
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_cycMOELogRow(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                        INT8U **ptrResp,                          //!< [inout] response buffer
                        INT16U *sizResp,                          //!< [inout] response buffer size
                        BOOLEAN __attribute__((unused)) validate, //!< not used
                        INT16U *errorCode)                        //!< [out] return error code
{
  // Variables that are specific to log type
  TYPE_log_header head;
  TYPE_MOE_log_entry logRecord;
  const char *logFileName = SNAP_CYC_MOE_LOG;
  INT8U dataBlock[SIZE_MOE_ROW];

  // Variables that are generic for all log types
  long filePosition = 0;
  FILE *logFp = NULL; //!< file descriptor for log file
  INT8U *dataptr = NULL;
  INT32U tempVal = 0;
  INT8U ii = 0;
  int recordNumber = 0;
  INT16U requestedIndex = 0;

  memset(&head, 0, sizeof(head));
  memset(&logRecord, 0, sizeof(logRecord));
  memset(dataBlock, 0, sizeof(dataBlock));

  if (ptrMsg->boIsWriteTheValue) {
    *errorCode = SNMPERRORREADONLY;
    return (FALSE);
  }

  // check if this is a GETNEXT request, just return zero to avoid file errors that would abort a MIB walk
  if (ptrMsg->usInPDUtype == SNMPREQUESTGETNEXT) { // Check for GET NEXT
    *errorCode = SNMPERRORNOERROR;
    memset(dataBlock, 0, sizeof(dataBlock)); // return an octet string of zeroes
    return bAppendOctet(dataBlock, ptrResp, sizResp, SIZE_MOE_ROW, errorCode);
  }

  // check to see if start position is set
  if ((psNtcipStatus->cycleMOELogCurReadPointer == -1) || (psATCsys->upTime > psNtcipStatus->cycleMOELogLockoutTime)) {
    // start position not set or not valid anymore
    // This is an unconventional use of BadValue, but we wanted a unique error code
    *errorCode = SNMPERRORBADVALUE;
    return (FALSE);
  } else {
    // move the lockout timer forward to prevent timeout during a sequence of gets
    psNtcipStatus->cycleMOELogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME;
  }

  // open log file in the ntcip sandbox (file should always exist)
  logFp = fopen(logFileName, "r");
  if (logFp == NULL) {
    *errorCode = SNMPERRORGENERALERROR;
    return (FALSE);
  }

  // read header (there should always be a valid header)
  if (fread(&head, sizeof(head), 1, logFp) != 1) {
    *errorCode = SNMPERRORGENERALERROR;
    fclose(logFp);
    return (FALSE);
  }

  // check if requested index is available in log
  requestedIndex = ptrMsg->usObjectIndex[0];
  if (requestedIndex > head.numEntries - psNtcipStatus->cycleMOELogCurReadPointer) {
    *errorCode = SNMPERRORNOSUCHNAME;
    fclose(logFp);
    return (FALSE);
  }

  // calculate requested record position
  recordNumber = head.firstEntry + psNtcipStatus->cycleMOELogCurReadPointer + (requestedIndex - 1);
  if (recordNumber >= MAX_MOE_LOGS) {
    recordNumber -= MAX_MOE_LOGS;
  }
  filePosition = (recordNumber * sizeof(logRecord)) + sizeof(head);

  // read record at requested position
  if ((fseek(logFp, filePosition, SEEK_SET) != 0) || (fread(&logRecord, sizeof(logRecord), 1, logFp) != 1) || (logRecord.sequenceNum == 0)) {
    *errorCode = SNMPERRORGENERALERROR;
    fclose(logFp);
    return (FALSE);
  }

  // valid record was found, serialize it into a data block according to the MIB definition of EntryData
  memset(dataBlock, 0, sizeof(dataBlock));

  tempVal = logRecord.sequenceNum;
  for (ii = 0; ii < 4; ii++) {
    dataBlock[3 - ii] = (INT8U)tempVal;
    tempVal = tempVal >> 8;
  }
  tempVal = logRecord.timestamp;
  for (ii = 0; ii < 4; ii++) {
    dataBlock[7 - ii] = (INT8U)tempVal;
    tempVal = tempVal >> 8;
  }
  dataBlock[8] = logRecord.pattern;
  dataBlock[9] = logRecord.cycleLength;
  dataBlock[10] = logRecord.cycleStatus;
  dataBlock[11] = logRecord.cycleFlags;
  dataptr = &dataBlock[12];
  for (ii = 0; ii < 16; ii++) {
    *dataptr++ = (INT8U)((logRecord.splitTime[ii] + 9) / 10);
    *dataptr++ = (INT8U)((logRecord.actualSplit[ii] + 9) / 10);
    *dataptr++ = logRecord.reasonForTerm[ii];
  }

  // success
  *errorCode = SNMPERRORNOERROR;
  fclose(logFp);
  return bAppendOctet(dataBlock, ptrResp, sizResp, SIZE_MOE_ROW, errorCode);
} // end fn_cycMOELogRow

//*******************************************************************************
//! function for Controller log number of entries
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_controllerLogNumEntries(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                                   INT8U **ptrResp,                          //!< [inout] response buffer
                                   INT16U *sizResp,                          //!< [inout] response buffer size
                                   BOOLEAN __attribute__((unused)) validate, //!< not used
                                   INT16U *errorCode)                        //!< [out] return error code
{
  int numEntries = 0;

  if (ptrMsg->boIsWriteTheValue) {
    *errorCode = SNMPERRORREADONLY;
    return (FALSE);
  }

  // check if this is a GETNEXT request, just return zero to avoid file errors that would abort a MIB walk
  if (ptrMsg->usInPDUtype == SNMPREQUESTGETNEXT) { // Check for GET NEXT
    *errorCode = SNMPERRORNOERROR;
    return bAppendUInt(0, ptrResp, sizResp, errorCode); // return zero
  }

  // check to see if start position is set
  if ((psNtcipStatus->controllerLogCurReadPointer == -1) || (psATCsys->upTime > psNtcipStatus->controllerLogLockoutTime)) {
    // start position not set or not valid anymore
    // This is an unconventional use of BadValue, but we wanted a unique error code
    *errorCode = SNMPERRORBADVALUE;
    return (FALSE);
  }

  numEntries = controllerLogSnapshotNumEntries - psNtcipStatus->controllerLogCurReadPointer;
  if (numEntries < 0) {
    *errorCode = SNMPERRORGENERALERROR;
    return FALSE;
  }

  *errorCode = SNMPERRORNOERROR;
  return bAppendUInt((INT32U)numEntries, ptrResp, sizResp, errorCode);
} // end fn_controllerLogNumEntries()

//*******************************************************************************
//! function for Controller log read action
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_controllerLogReadAction(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                                   INT8U **ptrResp,                          //!< [inout] response buffer
                                   INT16U *sizResp,                          //!< [inout] response buffer size
                                   BOOLEAN __attribute__((unused)) validate, //!< not used
                                   INT16U *errorCode)                        //!< [out] return error code
{
  INT32U value = 0;
  INT16U size = 0;
  INT16S newPtr = 0;

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {

    if (!bDecodeGaugeValue(&ptrMsg->ucReadPointer, &value, &size, errorCode)) {
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }

    if (value == 0) {
      // Clear start position
      psNtcipStatus->controllerLogCurReadPointer = -1;
      psNtcipStatus->controllerLogLockoutTime = 0;
      controllerLogStartSeqNum = 0;
      controllerLogStartTimestamp = 0;
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
    } else if (psATCsys->upTime <= psNtcipStatus->controllerLogLockoutTime) {
      // Don't allow start position to be changed if lockout timer is active
      *errorCode = SNMPERRORREADONLY;
      return (FALSE);
    }

    if (OID[ptrMsg->usObjectRow].oidPart[6] == 4) {
      newPtr = setCtlrLogReadPointer_r(value, 0, psNtcipStatus);
    } else {
      newPtr = setCtlrLogReadPointer_r(0, value, psNtcipStatus);
    }
    // check if log is empty or error occured
    if (newPtr < 0) {
      psNtcipStatus->controllerLogCurReadPointer = -1;
      *errorCode = SNMPERRORBADVALUE; // requested value is not available
      return (FALSE);
    } else {
      psNtcipStatus->controllerLogCurReadPointer = newPtr;
      psNtcipStatus->controllerLogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME;
    }
    if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
      return TRUE;
    }
    return bAppendGaugeValue(value, ptrResp, sizResp, errorCode);
  }

  // If we got here then we are just reading the value
  if (psATCsys->upTime > psNtcipStatus->controllerLogLockoutTime) {
    // if lock timer expired, the index is no longer valid, so return 0
    return bAppendGaugeValue(0, ptrResp, sizResp, errorCode);
  }
  if (OID[ptrMsg->usObjectRow].oidPart[6] == 4) {
    return bAppendGaugeValue(controllerLogStartSeqNum, ptrResp, sizResp, errorCode);
  } else {
    return bAppendGaugeValue(controllerLogStartTimestamp, ptrResp, sizResp, errorCode);
  }
}

//*******************************************************************************
//! function for Controller log clearing
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_controllerLogClearAction(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                                    INT8U **ptrResp,                          //!< [inout] response buffer
                                    INT16U *sizResp,                          //!< [inout] response buffer size
                                    BOOLEAN __attribute__((unused)) validate, //!< not used
                                    INT16U *errorCode)                        //!< [out] return error code
{
  static INT32U clearTime = 0;   // static so last value can be returned for a get
  static INT32U clearSeqNum = 0; // static so last value can be returned for a get
  BOOLEAN isSeqNum = FALSE;      // true if requested value is sequence number, else it is a timestamp
  INT16U size = 0;

  if (ptrMsg->boIsWriteTheValue) {
    // Do not allow log to be cleared if lockout timer is active
    if (psATCsys->upTime < psNtcipStatus->controllerLogLockoutTime) {
      *errorCode = SNMPERRORREADONLY;
      return (FALSE);
    }

    if (OID[ptrMsg->usObjectRow].oidPart[6] == 6) {
      isSeqNum = TRUE;
    } else {
      isSeqNum = FALSE;
    }
    if (isSeqNum) {
      if (!bDecodeGaugeValue(&ptrMsg->ucReadPointer, &clearSeqNum, &size, errorCode)) {
        *errorCode = SNMPERRORGENERALERROR;
        return (FALSE);
      }
      clearTime = 0;
    } else {
      if (!bDecodeGaugeValue(&ptrMsg->ucReadPointer, &clearTime, &size, errorCode)) {
        *errorCode = SNMPERRORGENERALERROR;
        return (FALSE);
      }
      clearSeqNum = 0;
    }
    if (!deleteCtlrLogEntries(clearSeqNum, clearTime, CTLR_LOG_ALL_LOGS)) {
      *errorCode = SNMPERRORGENERALERROR;
      return (FALSE);
    }
    if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
      return TRUE;
    }
  }
  if (isSeqNum) {
    return bAppendGaugeValue(clearSeqNum, ptrResp, sizResp, errorCode);
  } else {
    return bAppendGaugeValue(clearTime, ptrResp, sizResp, errorCode);
  }
}

//*******************************************************************************
//! function for Controller Log Row in table
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_controllerLogRow(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                            INT8U **ptrResp,                          //!< [inout] response buffer
                            INT16U *sizResp,                          //!< [inout] response buffer size
                            BOOLEAN __attribute__((unused)) validate, //!< not used
                            INT16U *errorCode)                        //!< [out] return error code
{
  INT8U dataBlock[SIZE_CNTRL_LOG_ROW] = {0};
  INT32U tempVal = 0;
  INT8U ii = 0;
  INT16U myReadPointer = 0;
  TYPE_CTLR_LOG_msg_entry logRecord;
  INT16S ret = 0;

  memset(&logRecord, 0, sizeof(logRecord));

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    *errorCode = SNMPERRORREADONLY;
    return (FALSE);
  }

  // check if this is a GETNEXT request, just return zero to avoid file errors that would abort a MIB walk
  if (ptrMsg->usInPDUtype == SNMPREQUESTGETNEXT) { // Check for GET NEXT
    *errorCode = SNMPERRORNOERROR;
    memset(dataBlock, 0, sizeof(dataBlock)); // return an octet string of zeroes
    return bAppendOctet(dataBlock, ptrResp, sizResp, SIZE_CNTRL_LOG_ROW, errorCode);
  }

  // check to see if start position is set
  if ((psNtcipStatus->controllerLogCurReadPointer == -1) || (psATCsys->upTime > psNtcipStatus->controllerLogLockoutTime)) {
    // start position not set or not valid anymore
    // This is an unconventional use of BadValue, but we wanted a unique error code
    *errorCode = SNMPERRORBADVALUE;
    return (FALSE);
  } else {
    // move the lockout timer forward to prevent timeout during a sequence of gets
    psNtcipStatus->controllerLogLockoutTime = psATCsys->upTime + LOG_LOCK_OUT_TIME;
  }

  myReadPointer = psNtcipStatus->controllerLogCurReadPointer + ptrMsg->usObjectIndex[0]; // get row position
  ret = getCtlrLogEntryForNtcip_r(&logRecord, myReadPointer, psNtcipStatus);
  if (ret <= 0) {
    *errorCode = SNMPERRORNOSUCHNAME;
    return (FALSE);
  }

  memset(dataBlock, 0, SIZE_CNTRL_LOG_ROW);
  tempVal = logRecord.seqNum;
  for (ii = 0; ii < 4; ii++) {
    dataBlock[3 - ii] = (INT8U)tempVal;
    tempVal = tempVal >> 8;
  }
  tempVal = logRecord.timestamp;
  for (ii = 0; ii < 4; ii++) {
    dataBlock[7 - ii] = (INT8U)tempVal;
    tempVal = tempVal >> 8;
  }
  dataBlock[8] = logRecord.reportType;
  // Last by of logMessage is cut off because dataBlock size is defined by MIB, cannot be changed
  memcpy(&dataBlock[9], logRecord.logMessage, CTLR_LOG_ENTRY_DATA_LEN);

  return bAppendOctet(dataBlock, ptrResp, sizResp, SIZE_CNTRL_LOG_ROW, errorCode);
}

BOOLEAN bIsLogicFunctionDeprecated(INT8U u8Func, BOOLEAN bIsInputFunction)
{
  const char **ppcFunctionTable = NULL;

  if (bIsInputFunction) {
    if (u8Func >= IOGI_NUMIDS) {
      return TRUE;
    }
    ppcFunctionTable = IoLogicInputFuncs_name;
  } else {
    if (u8Func >= IOGO_NUMIDS) {
      return TRUE;
    }
    ppcFunctionTable = IoLogicOutputFuncs_name;
  }
  if (strstr(ppcFunctionTable[u8Func], DEPRECATED_STRING_ID) || strstr(ppcFunctionTable[u8Func], CONTROL_IN_STRING_ID)) {
    return TRUE;
  }

  return FALSE;
}

//*******************************************************************************
//! function for IO Logic Gates
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_ioLogicGates(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                        INT8U **ptrResp,        //!< [inout] response buffer
                        INT16U *sizResp,        //!< [inout] response buffer size
                        BOOLEAN validate,       //!< only perform dry-run write if set
                        INT16U *errorCode)      //!< [out] return error code
{
  INT8U myValue = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &myValue, errorCode)) {
      if ((myValue < OID[ptrMsg->usObjectRow].oidMin) || (myValue > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      switch (OID[ptrMsg->usObjectRow].oidPart[9]) {
        case 2: // mcAtcIoLogicType
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].type = myValue;
          break;
        case 3: // mcAtcIoLogicOutputMode
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].outMode = myValue;
          break;
        case 4: // mcAtcIoLogicOutputInvert
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].outputInvert = myValue;
          break;
        case 5: // mcAtcIoLogicOutputDelay
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].outputDelay = myValue;
          break;
        case 6: // mcAtcIoLogicOutputExtension
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].outputExtension = myValue;
          break;
        case 7: // mcAtcIoLogicOutputFunction
          if (bIsLogicFunctionDeprecated(myValue, FALSE)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].outputFunc = myValue;
          break;
        case 8: // mcAtcIoLogicOutputFunctionIndex
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].outputFuncIdx = myValue;
          break;
        case 9: // mcAtcIoLogicInput1Invert
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[0].invert = myValue;
          break;
        case 10: // mcAtcIoLogicInput1Delay
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[0].delay = myValue;
          break;
        case 11: // mcAtcIoLogicInput1Extension
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[0].extension = myValue;
          break;
        case 12: // mcAtcIoLogicInput1Function
          if (bIsLogicFunctionDeprecated(myValue, TRUE)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[0].func = myValue;
          break;
        case 13: // mcAtcIoLogicInput1FunctionIndex
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[0].funcIdx = myValue;
          break;
        case 14: // mcAtcIoLogicInput2Invert
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[1].invert = myValue;
          break;
        case 15: // mcAtcIoLogicInput2Delay
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[1].delay = myValue;
          break;
        case 16: // mcAtcIoLogicInput2Extension
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[1].extension = myValue;
          break;
        case 17: // mcAtcIoLogicInput2Function
          if (bIsLogicFunctionDeprecated(myValue, TRUE)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[1].func = myValue;
          break;
        case 18: // mcAtcIoLogicInput2FunctionIndex
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[1].funcIdx = myValue;
          break;
        case 19: // mcAtcIoLogicInput3Invert
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[2].invert = myValue;
          break;
        case 20: // mcAtcIoLogicInput3Delay
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[2].delay = myValue;
          break;
        case 21: // mcAtcIoLogicInput3Extension
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[2].extension = myValue;
          break;
        case 22: // mcAtcIoLogicInput3Function
          if (bIsLogicFunctionDeprecated(myValue, TRUE)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[2].func = myValue;
          break;
        case 23: // mcAtcIoLogicInput3FunctionIndex
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[2].funcIdx = myValue;
          break;
        case 24: // mcAtcIoLogicInput4Invert
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[3].invert = myValue;
          break;
        case 25: // mcAtcIoLogicInput4Delay
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[3].delay = myValue;
          break;
        case 26: // mcAtcIoLogicInput4Extension
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[3].extension = myValue;
          break;
        case 27: // mcAtcIoLogicInput4Function
          if (bIsLogicFunctionDeprecated(myValue, TRUE)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[3].func = myValue;
          break;
        case 28: // mcAtcIoLogicInput4FunctionIndex
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[3].funcIdx = myValue;
          break;
        case 29: // mcAtcIoLogicDelayExtendUnits
          ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].delayExtendUnits = myValue;
          break;
        default:
          *errorCode = SNMPERRORNOSUCHNAME;
          return (FALSE);
      }
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(myValue, ptrResp, sizResp, errorCode);
    } else {
      return (FALSE);
    }
  }

  switch (OID[ptrMsg->usObjectRow].oidPart[9]) {
    case 2: // mcAtcIoLogicType
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].type, ptrResp, sizResp, errorCode);
    case 3: // mcAtcIoLogicOutputMode
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].outMode, ptrResp, sizResp, errorCode);
    case 4: // mcAtcIoLogicOutputInvert
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].outputInvert, ptrResp, sizResp, errorCode);
    case 5: // mcAtcIoLogicOutputDelay
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].outputDelay, ptrResp, sizResp, errorCode);
    case 6: // mcAtcIoLogicOutputExtension
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].outputExtension, ptrResp, sizResp, errorCode);
    case 7: // mcAtcIoLogicOutputFunction
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].outputFunc, ptrResp, sizResp, errorCode);
    case 8: // mcAtcIoLogicOutputFunctionIndex
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].outputFuncIdx, ptrResp, sizResp, errorCode);
    case 9: // mcAtcIoLogicInput1Invert
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[0].invert, ptrResp, sizResp, errorCode);
    case 10: // mcAtcIoLogicInput1Delay
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[0].delay, ptrResp, sizResp, errorCode);
    case 11: // mcAtcIoLogicInput1Extension
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[0].extension, ptrResp, sizResp, errorCode);
    case 12: // mcAtcIoLogicInput1Function
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[0].func, ptrResp, sizResp, errorCode);
    case 13: // mcAtcIoLogicInput1FunctionIndex
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[0].funcIdx, ptrResp, sizResp, errorCode);
    case 14: // mcAtcIoLogicInput2Invert
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[1].invert, ptrResp, sizResp, errorCode);
    case 15: // mcAtcIoLogicInput2Delay
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[1].delay, ptrResp, sizResp, errorCode);
    case 16: // mcAtcIoLogicInput2Extension
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[1].extension, ptrResp, sizResp, errorCode);
    case 17: // mcAtcIoLogicInput2Function
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[1].func, ptrResp, sizResp, errorCode);
    case 18: // mcAtcIoLogicInput2FunctionIndex
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[1].funcIdx, ptrResp, sizResp, errorCode);
    case 19: // mcAtcIoLogicInput3Invert
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[2].invert, ptrResp, sizResp, errorCode);
    case 20: // mcAtcIoLogicInput3Delay
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[2].delay, ptrResp, sizResp, errorCode);
    case 21: // mcAtcIoLogicInput3Extension
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[2].extension, ptrResp, sizResp, errorCode);
    case 22: // mcAtcIoLogicInput3Function
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[2].func, ptrResp, sizResp, errorCode);
    case 23: // mcAtcIoLogicInput3FunctionIndex
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[2].funcIdx, ptrResp, sizResp, errorCode);
    case 24: // mcAtcIoLogicInput4Invert
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[3].invert, ptrResp, sizResp, errorCode);
    case 25: // mcAtcIoLogicInput4Delay
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[3].delay, ptrResp, sizResp, errorCode);
    case 26: // mcAtcIoLogicInput4Extension
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[3].extension, ptrResp, sizResp, errorCode);
    case 27: // mcAtcIoLogicInput4Function
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[3].func, ptrResp, sizResp, errorCode);
    case 28: // mcAtcIoLogicInput4FunctionIndex
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].input[3].funcIdx, ptrResp, sizResp, errorCode);
    case 29: // mcAtcIoLogicDelayExtendUnits
      return bAppendUInt(ptrMsg->ptNtcipParameters->ioLogicGateConfig[ptrMsg->usObjectIndex[0] - 1].delayExtendUnits, ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
}

//*******************************************************************************
//! Action function to handle standard ASC pattern table
//! Note: Action function is required because the db array sizes do not match MAX_PATTERNS
//! @return       TRUE if no error
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_ascPatternTable(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                           INT8U **ptrResp,        //!< [inout] response buffer
                           INT16U *sizResp,        //!< [inout] response buffer size
                           BOOLEAN validate,       //!< only perform dry-run write if set
                           INT16U *errorCode)      //!< [out] return error code
{
  INT8U ucValue = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
      if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
        case 2: // patternCycleTime
          ptrMsg->ptNtcipParameters->patternCycleTime[ptrMsg->usObjectIndex[0] - 1] = ucValue;
          break;
        case 3: // patternOffsetTime
          ptrMsg->ptNtcipParameters->patternOffsetTime[ptrMsg->usObjectIndex[0] - 1] = ucValue;
          break;
        case 4: // patternSplitNumber
          ptrMsg->ptNtcipParameters->patternSplitNumber[ptrMsg->usObjectIndex[0] - 1] = ucValue;
          break;
        case 5: // patternSequenceNumber
          ptrMsg->ptNtcipParameters->patternSequenceNumber[ptrMsg->usObjectIndex[0] - 1] = ucValue;
          break;
        default:
          *errorCode = SNMPERRORNOSUCHNAME;
          return (FALSE);
      }
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
    } else {
      return (FALSE);
    }
  }

  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 2: // patternCycleTime
      return bAppendUInt(ptrMsg->ptNtcipParameters->patternCycleTime[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 3: // patternOffsetTime
      return bAppendUInt(ptrMsg->ptNtcipParameters->patternOffsetTime[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 4: // patternSplitNumber
      return bAppendUInt(ptrMsg->ptNtcipParameters->patternSplitNumber[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 5: // patternSequenceNumber
      return bAppendUInt(ptrMsg->ptNtcipParameters->patternSequenceNumber[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
}

static BOOLEAN fn_mcRingOffsetTable(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                                    INT8U **ptrResp,        //!< [inout] response buffer
                                    INT16U *sizResp,        //!< [inout] response buffer size
                                    BOOLEAN validate,       //!< only perform dry-run write if set
                                    INT16U *errorCode)      //!< [out] return error code
{
  INT16U u16Value = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt2(&ptrMsg->ucReadPointer, &u16Value, errorCode)) {
      if ((u16Value < OID[ptrMsg->usObjectRow].oidMin) || (u16Value > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      switch (OID[ptrMsg->usObjectRow].oidPart[7]) {
        case 1: // mcAtcPatternRingOffset
          ptrMsg->ptNtcipParameters->u16McAtcPatternRingOffset[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1] = u16Value;
          break;
        default:
          break;
      }
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(u16Value, ptrResp, sizResp, errorCode);
    } else {
      return (FALSE);
    }
  }

  switch (OID[ptrMsg->usObjectRow].oidPart[7]) {
    case 1: // mcAtcPatternRingOffset
      return bAppendUInt(ptrMsg->ptNtcipParameters->u16McAtcPatternRingOffset[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1], ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
}

//*******************************************************************************
//! Action function to handle custom McCain pattern table
//! Note: Action function is required because the db array sizes do not match MAX_PATTERNS
//! @return       TRUE if no error
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_mcPatternTable(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                          INT8U **ptrResp,        //!< [inout] response buffer
                          INT16U *sizResp,        //!< [inout] response buffer size
                          BOOLEAN validate,       //!< only perform dry-run write if set
                          INT16U *errorCode)      //!< [out] return error code
{
  INT8U ucValue = 0;
  INT16U usValue = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    if ((OID[ptrMsg->usObjectRow].oidPart[8] == 15) || (OID[ptrMsg->usObjectRow].oidPart[8] == 22) || (OID[ptrMsg->usObjectRow].oidPart[8] == 23)) {
      // mcAtcPatternMax2Phases, mcAtcPatternMax3Phases and mcAtcPatternMax3Phases
      if (bDecodeUInt2(&ptrMsg->ucReadPointer, &usValue, errorCode)) {
        if ((usValue < OID[ptrMsg->usObjectRow].oidMin) || (usValue > OID[ptrMsg->usObjectRow].oidMax)) {
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
        if (validate) {
          return (TRUE);
        }
        switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
          case 15: // mcAtcPatternMax2Phases
            ptrMsg->ptNtcipParameters->mcAtcPatternMax2Phases[ptrMsg->usObjectIndex[0] - 1] = usValue;
            break;

          case 22: // mcAtcPatternMax3Phases
            ptrMsg->ptNtcipParameters->mcAtcPatternMax3Phases[ptrMsg->usObjectIndex[0] - 1] = usValue;
            break;

          case 23: // mcAtcPatternMax4Phases
            ptrMsg->ptNtcipParameters->mcAtcPatternMax4Phases[ptrMsg->usObjectIndex[0] - 1] = usValue;
            break;
          default:
            break;
        }
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(usValue, ptrResp, sizResp, errorCode);
      } else {
        return (FALSE);
      }
    } else {
      if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
        if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
        if (validate) {
          return (TRUE);
        }
        switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
          case 1: // mcAtcPatternCoordCorrectionMode
            ptrMsg->ptNtcipParameters->mcAtcPatternCoordCorrectionMode[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 2: // mcAtcPatternCoordMaximumMode
            ptrMsg->ptNtcipParameters->mcAtcPatternCoordMaximumMode[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 3: // mcAtcPatternCoordForceMode
            ptrMsg->ptNtcipParameters->mcAtcPatternCoordForceMode[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 4: // mcAtcPatternCoordPermStrategy
            ptrMsg->ptNtcipParameters->mcAtcPatternCoordPermStrategy[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 5: // mcAtcPatternCoordOmitStrategy
            ptrMsg->ptNtcipParameters->mcAtcPatternCoordOmitStrategy[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 6: // mcAtcPatternCoordNoEarlyReturn
            ptrMsg->ptNtcipParameters->mcAtcPatternCoordNoEarlyReturn[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 7: // mcAtcPatternPhaseTimingSet
            ptrMsg->ptNtcipParameters->mcAtcPatternPhaseTimingSet[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 8: // mcAtcPatternPhaseOptionSet
            ptrMsg->ptNtcipParameters->mcAtcPatternPhaseOptionSet[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 9: // mcAtcPatternVehOverlapSet
            ptrMsg->ptNtcipParameters->mcAtcPatternVehOverlapSet[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 10: // mcAtcPatternVehDetSet
            ptrMsg->ptNtcipParameters->mcAtcPatternVehDetSet[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 11: // mcAtcPatternVehDetDiagSet
            ptrMsg->ptNtcipParameters->mcAtcPatternVehDetDiagSet[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 12: // mcAtcPatternPedDetSet
            ptrMsg->ptNtcipParameters->mcAtcPatternPedDetSet[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 13: // mcAtcPatternPedDetDiagSet
            ptrMsg->ptNtcipParameters->mcAtcPatternPedDetDiagSet[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 14: // mcAtcPatternDetectorReset
            ptrMsg->ptNtcipParameters->mcAtcPatternDetectorReset[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 16: // mcAtcPatternTexasDiamondType
            ptrMsg->ptNtcipParameters->mcAtcPatternTexasDiamondType[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 17: // mcAtcPatternPrioritySet
            ptrMsg->ptNtcipParameters->mcAtcPatternPrioritySet[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 18: // mcAtcPatternPedOverlapSet
            ptrMsg->ptNtcipParameters->mcAtcPatternPedOverlapSet[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 19: // mcAtcPatternCoordPercentValues
            ptrMsg->ptNtcipParameters->mcAtcPatternCoordPercentValues[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 20: // mcAtcPatternActuatedCoordEnable
            ptrMsg->ptNtcipParameters->mcAtcPatternActuatedCoordEnable[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          case 21: // mcAtcPatternActuatedCoordValue
            ptrMsg->ptNtcipParameters->mcAtcPatternActuatedCoordValue[ptrMsg->usObjectIndex[0] - 1] = ucValue;
            break;
          default:
            *errorCode = SNMPERRORNOSUCHNAME;
            return (FALSE);
        }
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      } else {
        return (FALSE);
      }
    }
  }

  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 1: // mcAtcPatternCoordCorrectionMode
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternCoordCorrectionMode[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 2: // mcAtcPatternCoordMaximumMode
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternCoordMaximumMode[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 3: // mcAtcPatternCoordForceMode
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternCoordForceMode[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 4: // mcAtcPatternCoordPermStrategy
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternCoordPermStrategy[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 5: // mcAtcPatternCoordOmitStrategy
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternCoordOmitStrategy[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 6: // mcAtcPatternCoordNoEarlyReturn
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternCoordNoEarlyReturn[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 7: // mcAtcPatternPhaseTimingSet
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternPhaseTimingSet[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 8: // mcAtcPatternPhaseOptionSet
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternPhaseOptionSet[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 9: // mcAtcPatternVehOverlapSet
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternVehOverlapSet[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 10: // mcAtcPatternVehDetSet
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternVehDetSet[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 11: // mcAtcPatternVehDetDiagSet
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternVehDetDiagSet[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 12: // mcAtcPatternPedDetSet
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternPedDetSet[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 13: // mcAtcPatternPedDetDiagSet
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternPedDetDiagSet[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 14: // mcAtcPatternDetectorReset
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternDetectorReset[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 15: // mcAtcPatternMax2Phases
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternMax2Phases[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 16: // mcAtcPatternTexasDiamondType
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternTexasDiamondType[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 17: // mcAtcPatternPrioritySet
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternPrioritySet[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 18: // mcAtcPatternPedOverlapSet
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternPedOverlapSet[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 19: // mcAtcPatternCoordPercentValues
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternCoordPercentValues[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 20: // mcAtcPatternActuatedCoordEnable
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternActuatedCoordEnable[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 21: // mcAtcPatternActuatedCoordValue
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternActuatedCoordValue[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 22: // mcAtcPatternMax3Phases
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternMax3Phases[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 23: // mcAtcPatternMax4Phases
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPatternMax4Phases[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
}

//*******************************************************************************
//! function for custom phase parameter sets
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_phaseParms8U(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                        INT8U **ptrResp,        //!< [inout] response buffer
                        INT16U *sizResp,        //!< [inout] response buffer size
                        BOOLEAN validate,       //!< only perform dry-run write if set
                        INT16U *errorCode)      //!< [out] return error code
{
  INT8U ucValue = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
      if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
        case 2: // mcAtcPhaseWalk
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseWalk = ucValue;
          break;
        case 3: // mcAtcPhasePedestrianClear
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phasePedestrianClear = ucValue;
          break;
        case 4: // mcAtcPhaseMinimumGreen
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseMinimumGreen = ucValue;
          break;
        case 5: // mcAtcPhasePassage
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phasePassage = ucValue;
          break;
        case 6: // mcAtcPhaseMaximum1
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseMaximum1 = ucValue;
          break;
        case 7: // mcAtcPhaseMaximum2
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseMaximum2 = ucValue;
          break;
        case 8: // mcAtcPhaseYellowChange
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseYellowChange = ucValue;
          break;
        case 9: // mcAtcPhaseRedClear
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseRedClear = ucValue;
          break;
        case 10: // mcAtcPhaseRedRevert
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseRedRevert = ucValue;
          break;
        case 11: // mcAtcPhaseAddedInitial
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseAddedInitial = ucValue;
          break;
        case 12: // mcAtcPhaseMaximumInitial
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseMaximumInitial = ucValue;
          break;
        case 13: // mcAtcPhaseTimeBeforeReduction
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseTimeBeforeReduction = ucValue;
          break;
        case 14: // mcAtcPhaseCarsBeforeReduction
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseCarsBeforeReduction = ucValue;
          break;
        case 15: // mcAtcPhaseTimeToReduce
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseTimeToReduce = ucValue;
          break;
        case 16: // mcAtcPhaseReduceBy
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseReduceBy = ucValue;
          break;
        case 17: // mcAtcPhaseMinimumGap
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseMinimumGap = ucValue;
          break;
        case 18: // mcAtcPhaseDynamicMaxLimit
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseDynamicMaxLimit = ucValue;
          break;
        case 19: // mcAtcPhaseDynamicMaxStep
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseDynamicMaxStep = ucValue;
          break;
        case 25: // mcAtcPhaseAlternateWalk
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcAlternateWalk = ucValue;
          break;
        case 26: // mcAtcPhaseAdvanceWalk
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcAdvanceWalk = ucValue;
          break;
        case 27: // mcAtcPhaseDelayWalk
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcDelayWalk = ucValue;
          break;
        case 28: // mcAtcPhaseAlternatePassage
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcAlternatePassage = ucValue;
          break;
        case 29: // mcAtcPhaseStartDelay
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseStartDelay = ucValue;
          break;
        case 30: // mcAtcPhaseCondSvcMin
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseCondSvcMin = ucValue;
          break;
        case 31: // mcAtcPhaseGreenClear
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseGreenClear = ucValue;
          break;
        case 32: // mcAtcPhaseAlternatePedClear
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseAlternatePedClear = ucValue;
          break;
        case 33: // mcAtcPhaseAlternateMinGreen
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseAlternateMinGreen = ucValue;
          break;
        case 34: // mcAtcPhaseMaximum3
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseMaximum3 = ucValue;
          break;
        case 35: // mcAtcPhaseMaximum4
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseMaximum4 = ucValue;
          break;
        case 38: // mcAtc1202PhasePedAlternateClearance
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].u8PhaseAltClear = ucValue;
          break;
        case 39: // mcAtc1202PhasePedAlternateWalk
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].u8PhaseAltWalk = ucValue;
          break;

        default:
          *errorCode = SNMPERRORNOSUCHNAME;
          return (FALSE);
      }

      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
    } else {
      return (FALSE);
    }
  }
  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 2: // mcAtcPhaseWalk
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseWalk, ptrResp, sizResp, errorCode);
    case 3: // mcAtcPhasePedestrianClear
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phasePedestrianClear, ptrResp, sizResp, errorCode);
    case 4: // mcAtcPhaseMinimumGreen
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseMinimumGreen, ptrResp, sizResp, errorCode);
    case 5: // mcAtcPhasePassage
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phasePassage, ptrResp, sizResp, errorCode);
    case 6: // mcAtcPhaseMaximum1
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseMaximum1, ptrResp, sizResp, errorCode);
    case 7: // mcAtcPhaseMaximum2
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseMaximum2, ptrResp, sizResp, errorCode);
    case 8: // mcAtcPhaseYellowChange
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseYellowChange, ptrResp, sizResp, errorCode);
    case 9: // mcAtcPhaseRedClear
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseRedClear, ptrResp, sizResp, errorCode);
    case 10: // mcAtcPhaseRedRevert
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseRedRevert, ptrResp, sizResp, errorCode);
    case 11: // mcAtcPhaseAddedInitial
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseAddedInitial, ptrResp, sizResp, errorCode);
    case 12: // mcAtcPhaseMaximumInitial
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseMaximumInitial, ptrResp, sizResp, errorCode);
    case 13: // mcAtcPhaseTimeBeforeReduction
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseTimeBeforeReduction, ptrResp, sizResp, errorCode);
    case 14: // mcAtcPhaseCarsBeforeReduction
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseCarsBeforeReduction, ptrResp, sizResp, errorCode);
    case 15: // mcAtcPhaseTimeToReduce
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseTimeToReduce, ptrResp, sizResp, errorCode);
    case 16: // mcAtcPhaseReduceBy
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseReduceBy, ptrResp, sizResp, errorCode);
    case 17: // mcAtcPhaseMinimumGap
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseMinimumGap, ptrResp, sizResp, errorCode);
    case 18: // mcAtcPhaseDynamicMaxLimit
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseDynamicMaxLimit, ptrResp, sizResp, errorCode);
    case 19: // mcAtcPhaseDynamicMaxStep
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseDynamicMaxStep, ptrResp, sizResp, errorCode);

    case 25: // mcAtcPhaseAlternateWalk
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcAlternateWalk, ptrResp, sizResp, errorCode);
    case 26: // mcAtcPhaseAdvanceWalk
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcAdvanceWalk, ptrResp, sizResp, errorCode);
    case 27: // mcAtcPhaseDelayWalk
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcDelayWalk, ptrResp, sizResp, errorCode);
    case 28: // mcAtcPhaseAlternatePassage
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcAlternatePassage, ptrResp, sizResp, errorCode);
    case 29: // mcAtcPhaseStartDelay
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseStartDelay, ptrResp, sizResp, errorCode);
    case 30: // mcAtcPhaseCondSvcMin
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseCondSvcMin, ptrResp, sizResp, errorCode);
    case 31: // mcAtcPhaseGreenClear
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseGreenClear, ptrResp, sizResp, errorCode);
    case 32: // mcAtcPhaseAlternatePedClear
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseAlternatePedClear, ptrResp, sizResp, errorCode);
    case 33: // mcAtcPhaseAlternateMinGreen
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseAlternateMinGreen, ptrResp, sizResp, errorCode);
    case 34: // mcAtcPhaseMaximum3
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseMaximum3, ptrResp, sizResp, errorCode);
    case 35: // mcAtcPhaseMaximum4
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseMaximum4, ptrResp, sizResp, errorCode);
    case 38: // mcAtc1202PhasePedAlternateClearance
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].u8PhaseAltClear, ptrResp, sizResp, errorCode);
    case 39: // mcAtc1202PhasePedAlternateWalk
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].u8PhaseAltWalk, ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_phaseParms8U()

//*******************************************************************************
//! function for custom phase timer sets
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_phaseTimers(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                       INT8U **ptrResp,        //!< [inout] response buffer
                       INT16U *sizResp,        //!< [inout] response buffer size
                       BOOLEAN validate,       //!< only perform dry-run write if set
                       INT16U *errorCode)      //!< [out] return error code
{
  INT8U ucValue = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
      if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
        case 1 ... 24:
          *errorCode = SNMPERRORREADONLY;
          return (FALSE);

        default:
          *errorCode = SNMPERRORNOSUCHNAME;
          return (FALSE);
      }
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
    } else {
      return (FALSE);
    }
  }
  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 1: // mcAtcPhaseWalkTimer
      return bAppendUInt(psTrafficOut->pedWalkTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 2: // mcAtcPhasePedClearTimer
      return bAppendUInt(psTrafficOut->pedClrTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 3: // mcAtcPhaseMinimumGreenTimer
      return bAppendUInt(psTrafficOut->phaseGreenMinTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 4: // mcAtcPhasePassageTimer
      return bAppendUInt(psTrafficOut->phaseGreenPassageTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 5: // mcAtcPhaseMaxTimer
      return bAppendUInt(u16GetOffsetDownCounter(&(psTrafficOut->atPhaseGreenMaxTimer[ptrMsg->usObjectIndex[0] - 1])), ptrResp, sizResp, errorCode);
    case 6: // mcAtcPhaseYellowTimer
      return bAppendUInt(psTrafficOut->phaseYellowTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 7: // mcAtcPhaseRedClearTimer
      return bAppendUInt(psTrafficOut->phaseRedClrTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 8: // mcAtcPhaseRedRevertTimer
      return bAppendUInt(psTrafficOut->phaseRedRevertTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 9: // mcAtcPhaseInitialTimer
      return bAppendUInt(psTrafficOut->phaseGreenInitialTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 10: // mcAtcPhaseAdvanceWalkTimer
      return bAppendUInt(psTrafficOut->pedAdvWalkTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 11: // mcAtcPhaseDelayWalkTimer
      return bAppendUInt(psTrafficOut->pedDlyWalkTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 12: // mcAtcPhaseStartDelayTimer
      return bAppendUInt(psTrafficOut->phaseStartDelayTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 13: // mcAtcPhaseGreenClearTimer
      return bAppendUInt(psTrafficOut->phaseGreenClrTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 14: // mcAtcPhaseGapReductionTimer
      return bAppendUInt(psTrafficOut->gapredTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 15: // mcAtcPhaseGreenElapsedTimer
      return bAppendUInt(psTrafficOut->phaseGreenElapsedTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 16: // mcAtcPhaseYellowElapsedTimer
      return bAppendUInt(psTrafficOut->phaseYellowElapsedTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 17: // mcAtcPhaseRedElapsedTimer
      return bAppendUInt(psTrafficOut->phaseRedElapsedTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 18: // mcAtcPhaseWalkElapsedTimer
      return bAppendUInt(psTrafficOut->pedWalkElapsedTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 19: // mcAtcPhasePedClearElapsedTimer
      return bAppendUInt(psTrafficOut->pedClrElapsedTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 20: // mcAtcPhaseWaitTimer
      return bAppendUInt(psTrafficOut->u16PhaseWaitTimer[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 21: // mcAtcPhaseGreenElapsedTimerSec
      return bAppendUInt((psTrafficOut->phaseGreenElapsedTimer[ptrMsg->usObjectIndex[0] - 1] / 10), ptrResp, sizResp, errorCode);
    case 22: // mcAtcPhaseWalkElapsedTimerSec
      return bAppendUInt((psTrafficOut->pedWalkElapsedTimer[ptrMsg->usObjectIndex[0] - 1] / 10), ptrResp, sizResp, errorCode);
    case 23: // mcAtcPhasePedClearElapsedTimerSec
      return bAppendUInt((psTrafficOut->pedClrElapsedTimer[ptrMsg->usObjectIndex[0] - 1] / 10), ptrResp, sizResp, errorCode);
    case 24: // mcAtcPhaseWaitTimerSec
      return bAppendUInt((psTrafficOut->u16PhaseWaitTimer[ptrMsg->usObjectIndex[0] - 1] / 10), ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_phaseTimers()

//*******************************************************************************
//! function for custom phase options
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_phaseOptions(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                        INT8U **ptrResp,        //!< [inout] response buffer
                        INT16U *sizResp,        //!< [inout] response buffer size
                        BOOLEAN validate,       //!< only perform dry-run write if set
                        INT16U *errorCode)      //!< [out] return error code
{
  INT16U usValue = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt2(&ptrMsg->ucReadPointer, &usValue, errorCode)) {
      if ((usValue < OID[ptrMsg->usObjectRow].oidMin) || (usValue > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
        case 1: // mcAtcPhaseConfigOptions
          ptrMsg->ptNtcipParameters->mcAtcPhaseConfigOptions[ptrMsg->usObjectIndex[0] - 1] = usValue;
          break;
        case 21: // mcAtcPhaseOptions (Ignore bit 0)
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseOptions = usValue & 0xFFFE;
          break;
        case 24: // mcAtcPhaseOptions2
          ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseOptions2 = usValue;
          break;
        default:
          *errorCode = SNMPERRORNOSUCHNAME;
          return (FALSE);
      }
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(usValue, ptrResp, sizResp, errorCode);
    } else {
      return (FALSE);
    }
  }
  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 1: // mcAtcPhaseConfigOptions
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcPhaseConfigOptions[ptrMsg->usObjectIndex[0] - 1], ptrResp, sizResp, errorCode);
    case 21: // mcAtcPhaseOptions (Ignore bit 0)
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].phaseOptions & 0xFFFE, ptrResp, sizResp, errorCode);
    case 24: // mcAtcPhaseOptions2
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPhaseData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPhaseOptions2, ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_phaseOptions()

/*************************************************************************************************/
/*  Name       : fn_duplicatePhaseObjects                                                        */
/*                                                                                               */
/*  Description: In Omni, extension objects were added to the phase parameters. Also, all these  */
/*    phase parameters were duplicated into sets which can be selected to control the Omni       */
/*    controller. There were 4 objects which are shared by all sets; phaseStartup, phaseRing,    */
/*    phaseConcurrency and the enable bit (bit 0) of phaseOptions. Therefore, these objects      */
/*    are not replicated for each set. They can be set with their corresponding standard 1202    */
/*    phase objects of with the Omni objects (hence, duplicate phase objects). The reason for    */
/*    this duplication of objects is so that the entire group of phase settings may be made      */
/*    using Omni objects, with the correllary that only Omni objects will be used in the         */
/*    database file. If a user sets up the controller using only standard 1202 objects, the      */
/*    controller will operate according to the 1202 objects' descriptions.                       */
/*  Returns TRUE if no error, FALSE if error (error code in usErrorCode)                         */
/*************************************************************************************************/
BOOLEAN fn_duplicatePhaseObjects(TYPE_COMMS_MSG *psMsg, //!< [inout] message structure holding received message
                                 INT8U **psResp,        //!< [inout] response buffer
                                 INT16U *pu16SizResp,   //!< [inout] response buffer size
                                 BOOLEAN bValidate,     //!< only perform dry-run write if set
                                 INT16U *pu16ErrorCode) //!< [out] return error code
{
  enum {                              // These cannot be constants because the compiler doesn't consider a switch's case as a variable usage.
    DUPLICATE_PHASE_ITEM_CONFIG = 1,  // mcAtc1202PhaseConfigOptions
    DUPLICATE_PHASE_ITEM_STARTUP = 2, // mcAtc1202PhaseStartup
    DUPLICATE_PHASE_ITEM_RING = 3,    // mcAtc1202PhaseRing
    DUPLICATE_PHASE_ITEM_NUMBER = 8   // This is the part of the OID that distinguishes the item which called this routine
  };
  INT8U u8Index1 = psMsg->usObjectIndex[0] - 1; // The index to be used for all the objects
  INT16U u16UsValue = 0;
  INT8U u8UsValue = 0;

  *pu16ErrorCode = SNMPERRORNOERROR;
  // Handle this based on the type of object
  switch (OID[psMsg->usObjectRow].oidPart[DUPLICATE_PHASE_ITEM_NUMBER]) {
    case DUPLICATE_PHASE_ITEM_CONFIG:
      if (psMsg->boIsWriteTheValue) {
        if (bDecodeUInt2(&psMsg->ucReadPointer, &u16UsValue, pu16ErrorCode)) {
          if ((u16UsValue < OID[psMsg->usObjectRow].oidMin) || (u16UsValue > OID[psMsg->usObjectRow].oidMax)) {
            *pu16ErrorCode = SNMPERRORBADVALUE;
            return FALSE;
          }
          if (bValidate) {
            return TRUE;
          }
          psMsg->ptNtcipParameters->mcAtcPhaseConfigOptions[u8Index1] = u16UsValue & 0x01;
          if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
            return *pu16ErrorCode == SNMPERRORNOERROR ? TRUE : FALSE;
          }
          return bAppendUInt(u16UsValue, psResp, pu16SizResp, pu16ErrorCode);
        } else {
          return FALSE;
        }
      }
      return bAppendUInt(psMsg->ptNtcipParameters->mcAtcPhaseConfigOptions[u8Index1], psResp, pu16SizResp, pu16ErrorCode);
    case DUPLICATE_PHASE_ITEM_STARTUP:
      if (psMsg->boIsWriteTheValue) {
        if (bDecodeUInt1(&psMsg->ucReadPointer, &u8UsValue, pu16ErrorCode)) {
          if ((u8UsValue < OID[psMsg->usObjectRow].oidMin) || (u8UsValue > OID[psMsg->usObjectRow].oidMax)) {
            *pu16ErrorCode = SNMPERRORBADVALUE;
            return FALSE;
          }

          if (bValidate) {
            return TRUE;
          }

          // Check for invalid values, currently this value is used in other areas, if the value is not 1-6 it can cause a problem/crash.
          if (u8UsValue < PHS_STARTUP_OTHER) {
            u8UsValue = PHS_STARTUP_OTHER;
          } else if (u8UsValue > PHS_STARTUP_RED_CLEAR) {
            u8UsValue = PHS_STARTUP_RED_CLEAR;
          }

          psMsg->ptNtcipParameters->phaseStartup[u8Index1] = u8UsValue;

          if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
            return *pu16ErrorCode == SNMPERRORNOERROR ? TRUE : FALSE;
          }
          return bAppendUInt(u8UsValue, psResp, pu16SizResp, pu16ErrorCode);
        } else {
          return FALSE;
        }
      }
      return bAppendUInt(psMsg->ptNtcipParameters->phaseStartup[u8Index1], psResp, pu16SizResp, pu16ErrorCode);
    case DUPLICATE_PHASE_ITEM_RING:
      if (psMsg->boIsWriteTheValue) {
        if (bDecodeUInt1(&psMsg->ucReadPointer, &u8UsValue, pu16ErrorCode)) {
          if ((u8UsValue < OID[psMsg->usObjectRow].oidMin) || (u8UsValue > OID[psMsg->usObjectRow].oidMax)) {
            *pu16ErrorCode = SNMPERRORBADVALUE;
            return FALSE;
          }
          if (bValidate) {
            return TRUE;
          }
          psMsg->ptNtcipParameters->phaseRing[u8Index1] = u8UsValue;
          if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
            return *pu16ErrorCode == SNMPERRORNOERROR ? TRUE : FALSE;
          }
          return bAppendUInt(u8UsValue, psResp, pu16SizResp, pu16ErrorCode);
        } else {
          return FALSE;
        }
      }
      return bAppendUInt(psMsg->ptNtcipParameters->phaseRing[u8Index1], psResp, pu16SizResp, pu16ErrorCode);
    default:
      // This routine was called with an incorrect code
      return FALSE;
  }
} // end fn_phaseOptions()

//*******************************************************************************
//! function for NTCIP 1202 phase options
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_1202PhaseOptions(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                            INT8U **ptrResp,        //!< [inout] response buffer
                            INT16U *sizResp,        //!< [inout] response buffer size
                            BOOLEAN validate,       //!< only perform dry-run write if set
                            INT16U *errorCode)      //!< [out] return error code
{
  INT16U usValue = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt2(&ptrMsg->ucReadPointer, &usValue, errorCode)) {
      if ((usValue < OID[ptrMsg->usObjectRow].oidMin) || (usValue > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return (FALSE);
      }
      if (validate) {
        return (TRUE);
      }
      switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
        case 21: // phaseOptions
                 //  store multi-set options in first phase set
          ptrMsg->ptNtcipParameters->atPhaseData[0][ptrMsg->usObjectIndex[0] - 1].phaseOptions = usValue & 0xFFFE;
          // store Enabled Phase bit in mcAtcPhaseConfigOptions
          ptrMsg->ptNtcipParameters->mcAtcPhaseConfigOptions[ptrMsg->usObjectIndex[0] - 1] &= 0xFFFE;
          ptrMsg->ptNtcipParameters->mcAtcPhaseConfigOptions[ptrMsg->usObjectIndex[0] - 1] |= (usValue & 0x01);
          break;
        default:
          *errorCode = SNMPERRORNOSUCHNAME;
          return (FALSE);
      }
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
        return TRUE;
      }
      return bAppendUInt(usValue, ptrResp, sizResp, errorCode);
    } else {
      return (FALSE);
    }
  }
  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 21: // phaseOptions
             //  Combine multi-set phase options from first set with Enabled Phase bit from mcAtcPhaseConfigOptions
      return bAppendUInt((ptrMsg->ptNtcipParameters->atPhaseData[0][ptrMsg->usObjectIndex[0] - 1].phaseOptions & 0xFFFE) |
                             (ptrMsg->ptNtcipParameters->mcAtcPhaseConfigOptions[ptrMsg->usObjectIndex[0] - 1] & 0x01),
                         ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_1202PhaseOptions()

//*******************************************************************************
//! function for custom overlap parameter sets
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_overlapParms(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                        INT8U **ptrResp,        //!< [inout] response buffer
                        INT16U *sizResp,        //!< [inout] response buffer size
                        BOOLEAN validate,       //!< only perform dry-run write if set
                        INT16U *errorCode)      //!< [out] return error code
{
  INT8U ucValue = 0;
  INT16U usValue = 0;
  INT8U anOCTETvalue[MAX_PHASES];

  memset(anOCTETvalue, 0, sizeof(anOCTETvalue));

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 2:  // mcAtcOverlapType
      case 5:  // mcAtcOverlapTrailGreen
      case 6:  // mcAtcOverlapTrailYellow
      case 7:  // mcAtcOverlapTrailRed
      case 8:  // mcAtcOverlapStartDelay
      case 13: // mcAtcOverlapOptions
        if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
          if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;

      case 3:  // mcAtcOverlapIncludedPhases
      case 4:  // mcAtcOverlapModifierPhases
      case 9:  // mcAtcOverlapExcludedPhases
      case 10: // mcAtcOverlapExcludedPeds
      case 14: // mcAtcOverlapExcludedWalks
      case 16: // mcAtcOverlapExcludedPedOverlaps
        ptrMsg->usCurrentDataSize = sizeof(anOCTETvalue);
        if (bDecodeOctetValue(&ptrMsg->ucReadPointer, anOCTETvalue, &ptrMsg->usCurrentDataSize, errorCode)) {
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;

      case 11: // mcAtcOverlapNoTrailGreenClearPhases
      case 12: // mcAtcOverlapCallPhases
      case 15: // mcAtcOverlapNoTrailGreenNextPhases
        if (bDecodeUInt2(&ptrMsg->ucReadPointer, &usValue, errorCode)) {
          if ((usValue < OID[ptrMsg->usObjectRow].oidMin) || (usValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;
      default:
        break;
    }
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 2: // mcAtcOverlapType
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].overlapType = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      case 3: // mcAtcOverlapIncludedPhases
        if (!octStr2phaseBits(anOCTETvalue, ptrMsg->usCurrentDataSize, &ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].overlapIncludedPhases)) {
          // the conversion failed
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      case 4: // mcAtcOverlapModifierPhases
        if (!octStr2phaseBits(anOCTETvalue, ptrMsg->usCurrentDataSize, &ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].overlapModifierPhases)) {
          // the conversion failed
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      case 5: // mcAtcOverlapTrailGreen
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].overlapTrailGreen = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      case 6: // mcAtcOverlapTrailYellow
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].overlapTrailYellow = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      case 7: // mcAtcOverlapTrailRed
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].overlapTrailRed = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      case 8: // mcAtcOverlapStartDelay
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapStartDelay = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      case 9: // mcAtcOverlapExcludedPhases
        if (!octStr2phaseBits(anOCTETvalue, ptrMsg->usCurrentDataSize, &ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapExcludedPhases)) {
          // the conversion failed
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      case 10: // mcAtcOverlapExcludedPeds
        if (!octStr2phaseBits(anOCTETvalue, ptrMsg->usCurrentDataSize, &ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapExcludedPeds)) {
          // the conversion failed
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      case 11: // mcAtcOverlapNoTrailGreenClearPhases
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapNoTrailGreenClearPhases = usValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(usValue, ptrResp, sizResp, errorCode);
      case 12: // mcAtcOverlapCallPhases
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapCallPhases = usValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(usValue, ptrResp, sizResp, errorCode);
      case 13: // mcAtcOverlapOptions
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapOptions = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      case 14: // mcAtcOverlapExcludedWalks
        if (!octStr2phaseBits(anOCTETvalue, ptrMsg->usCurrentDataSize, &ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapExcludedWalks)) {
          // the conversion failed
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      case 15: // mcAtcOverlapNoTrailGreenNextPhases
        ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapNoTrailGreenNextPhases = usValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(usValue, ptrResp, sizResp, errorCode);
      case 16: // mcAtcOverlapExcludedPedOverlaps
        if (!octStr2phaseBits(anOCTETvalue, ptrMsg->usCurrentDataSize, &ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapExcludedPedOverlaps)) {
          // the conversion failed
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      default:
        *errorCode = SNMPERRORNOSUCHNAME;
        return (FALSE);
    }
  }

  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 2: // mcAtcOverlapType
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].overlapType, ptrResp, sizResp, errorCode);
    case 3: // mcAtcOverlapIncludedPhases
      ptrMsg->usCurrentDataSize = phaseBits2octStr(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].overlapIncludedPhases, anOCTETvalue);
      return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    case 4: // mcAtcOverlapModifierPhases
      ptrMsg->usCurrentDataSize = phaseBits2octStr(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].overlapModifierPhases, anOCTETvalue);
      return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    case 5: // mcAtcOverlapTrailGreen
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].overlapTrailGreen, ptrResp, sizResp, errorCode);
    case 6: // mcAtcOverlapTrailYellow
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].overlapTrailYellow, ptrResp, sizResp, errorCode);
    case 7: // mcAtcOverlapTrailRed
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].overlapTrailRed, ptrResp, sizResp, errorCode);
    case 8: // mcAtcOverlapStartDelay
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapStartDelay, ptrResp, sizResp, errorCode);
    case 9: // mcAtcOverlapExcludedPhases
      ptrMsg->usCurrentDataSize = phaseBits2octStr(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapExcludedPhases, anOCTETvalue);
      return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    case 10: // mcAtcOverlapExcludedPeds
      ptrMsg->usCurrentDataSize = phaseBits2octStr(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapExcludedPeds, anOCTETvalue);
      return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    case 11: // mcAtcOverlapNoTrailGreenClearPhases
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapNoTrailGreenClearPhases, ptrResp, sizResp, errorCode);
    case 12: // mcAtcOverlapCallPhases
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapCallPhases, ptrResp, sizResp, errorCode);
    case 13: // mcAtcOverlapOptions
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapOptions, ptrResp, sizResp, errorCode);
    case 14: // mcAtcOverlapExcludedWalks
      ptrMsg->usCurrentDataSize = phaseBits2octStr(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapExcludedWalks, anOCTETvalue);
      return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    case 15: // mcAtcOverlapNoTrailGreenNextPhases
      return bAppendUInt(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapNoTrailGreenNextPhases, ptrResp, sizResp, errorCode);
    case 16: // mcAtcOverlapExcludedPedOverlaps
      ptrMsg->usCurrentDataSize = phaseBits2octStr(ptrMsg->ptNtcipParameters->atOverlapData[ptrMsg->usObjectIndex[0] - 1].atVehOverlaps[ptrMsg->usObjectIndex[1] - 1].mcAtcOverlapExcludedPedOverlaps, anOCTETvalue);
      return bAppendOctet(anOCTETvalue, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_overlapParms()

//*******************************************************************************
//! function for custom vehicle detector parameter sets
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_vehDetectorParms(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                            INT8U **ptrResp,        //!< [inout] response buffer
                            INT16U *sizResp,        //!< [inout] response buffer size
                            BOOLEAN validate,       //!< only perform dry-run write if set
                            INT16U *errorCode)      //!< [out] return error code
{
  INT8U ucValue = 0;
  INT16U usValue = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 5:  // mcAtcVehicleDetectorDelay
      case 12: // mcAtcVehicleDetectorVOSLength
      case 14: // mcAtcVehicleDetectorExtraCallPhases
      case 15: // mcAtcVehicleDetectorCallOverlaps
      case 17: // mcAtc1202VehicleDetectorAvgVehicleLength
      case 18: // mcAtc1202VehicleDetectorLength
        if (bDecodeUInt2(&ptrMsg->ucReadPointer, &usValue, errorCode)) {
          if ((usValue < OID[ptrMsg->usObjectRow].oidMin) || (usValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;
      case 2:  // mcAtcVehicleDetectorOptions
      case 3:  // mcAtcVehicleDetectorCallPhase
      case 4:  // mcAtcVehicleDetectorSwitchPhase
      case 6:  // mcAtcVehicleDetectorExtend
      case 7:  // mcAtcVehicleDetectorQueueLimit
      case 8:  // mcAtcVehicleDetectorNoActivity
      case 9:  // mcAtcVehicleDetectorMaxPresence
      case 10: // mcAtcVehicleDetectorErraticCounts
      case 11: // mcAtcVehicleDetectorFailTime
      case 13: // mcAtcVehicleDetectorOptions2
      case 19: // mcAtc1202VehicleDetectorTravelMode
        if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
          if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;
      default:
        break;
    }

    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 2: // mcAtcVehicleDetectorOptions
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorOptions = ucValue;
        break;
      case 3: // mcAtcVehicleDetectorCallPhase
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorCallPhase = ucValue;
        break;
      case 4: // mcAtcVehicleDetectorSwitchPhase
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorSwitchPhase = ucValue;
        break;
      case 5: // mcAtcVehicleDetectorDelay
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorDelay = usValue;
        break;
      case 6: // mcAtcVehicleDetectorExtend
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorExtend = ucValue;
        break;
      case 7: // mcAtcVehicleDetectorQueueLimit
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorQueueLimit = ucValue;
        break;
      case 8: // mcAtcVehicleDetectorNoActivity
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorNoActivity = ucValue;
        break;
      case 9: // mcAtcVehicleDetectorMaxPresence
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorMaxPresence = ucValue;
        break;
      case 10: // mcAtcVehicleDetectorErraticCounts
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorErraticCounts = ucValue;
        break;
      case 11: // mcAtcVehicleDetectorFailTime
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorFailTime = ucValue;
        break;
      case 12: // mcAtcVehicleDetectorVOSLength
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcVehicleDetectorVOSLength = usValue;
        break;
      case 13: // mcAtcVehicleDetectorOptions2
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcVehicleDetectorOptions2 = ucValue;
        break;
      case 14: // mcAtcVehicleDetectorExtraCallPhases
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcVehicleDetectorExtraCallPhases = usValue;
        break;
      case 15: // mcAtcVehicleDetectorCallOverlaps
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcVehicleDetectorCallOverlaps = usValue;
        break;
      case 17: // mcAtc1202VehicleDetectorAvgVehicleLength
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].u16VehicleDetectorAvgVehicleLength = usValue;
        break;
      case 18: // mcAtc1202VehicleDetectorLength
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].u16VehicleDetectorLength = usValue;
        break;
      case 19: // mcAtc1202VehicleDetectorTravelMode
        ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].u8VehicleDetectorTravelMode = ucValue;
        break;
      default:
        *errorCode = SNMPERRORNOSUCHNAME;
        return (FALSE);
    }
    if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
      return TRUE;
    }
    if ((OID[ptrMsg->usObjectRow].oidPart[8] == 5) || (OID[ptrMsg->usObjectRow].oidPart[8] == 12)        // mcAtcVehicleDetectorDelay, mcAtcVehicleDetectorVOSLength
        || (OID[ptrMsg->usObjectRow].oidPart[8] == 14) || (OID[ptrMsg->usObjectRow].oidPart[8] == 15)) { // mcAtcVehicleDetectorExtraCallPhases, mcAtcVehicleDetectorCallOverlaps
      return bAppendUInt(usValue, ptrResp, sizResp, errorCode);
    } else {
      return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
    }
  }
  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 2: // mcAtcVehicleDetectorOptions
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorOptions, ptrResp, sizResp, errorCode);
    case 3: // mcAtcVehicleDetectorCallPhase
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorCallPhase, ptrResp, sizResp, errorCode);
    case 4: // mcAtcVehicleDetectorSwitchPhase
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorSwitchPhase, ptrResp, sizResp, errorCode);
    case 5: // mcAtcVehicleDetectorDelay
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorDelay, ptrResp, sizResp, errorCode);
    case 6: // mcAtcVehicleDetectorExtend
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorExtend, ptrResp, sizResp, errorCode);
    case 7: // mcAtcVehicleDetectorQueueLimit
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorQueueLimit, ptrResp, sizResp, errorCode);
    case 8: // mcAtcVehicleDetectorNoActivity
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorNoActivity, ptrResp, sizResp, errorCode);
    case 9: // mcAtcVehicleDetectorMaxPresence
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorMaxPresence, ptrResp, sizResp, errorCode);
    case 10: // mcAtcVehicleDetectorErraticCounts
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorErraticCounts, ptrResp, sizResp, errorCode);
    case 11: // mcAtcVehicleDetectorFailTime
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].vehicleDetectorFailTime, ptrResp, sizResp, errorCode);
    case 12: // mcAtcVehicleDetectorVOSLength
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcVehicleDetectorVOSLength, ptrResp, sizResp, errorCode);
    case 13: // mcAtcVehicleDetectorOptions2
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcVehicleDetectorOptions2, ptrResp, sizResp, errorCode);
    case 14: // mcAtcVehicleDetectorExtraCallPhases
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcVehicleDetectorExtraCallPhases, ptrResp, sizResp, errorCode);
    case 15: // mcAtcVehicleDetectorCallOverlaps
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcVehicleDetectorCallOverlaps, ptrResp, sizResp, errorCode);
    case 17: // mcAtc1202VehicleDetectorAvgVehicleLength
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].u16VehicleDetectorAvgVehicleLength, ptrResp, sizResp, errorCode);
    case 18: // mcAtc1202VehicleDetectorLength
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].u16VehicleDetectorLength, ptrResp, sizResp, errorCode);
    case 19: // mcAtc1202VehicleDetectorTravelMode
      return bAppendUInt(ptrMsg->ptNtcipParameters->atDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].u8VehicleDetectorTravelMode, ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_vehDetectorParms()

/*************************************************************************************************/
/*  Name       : fn_pedDetectorParms                                                             */
/*                                                                                               */
/*  Description: Function for custom pedestrian detector parameter sets.                         */
/*                                                                                               */
/*  Return     : TRUE if no error.                                                               */
/*               FALSE if error (error code in usErrorCode)                                      */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN fn_pedDetectorParms(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                            INT8U **ptrResp,        //!< [inout] response buffer
                            INT16U *sizResp,        //!< [inout] response buffer size
                            BOOLEAN validate,       //!< only perform dry-run write if set
                            INT16U *errorCode)      //!< [out] return error code
{
  INT8U ucValue = 0;
  INT16U usValue = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    if ((OID[ptrMsg->usObjectRow].oidPart[8] == 7) || (OID[ptrMsg->usObjectRow].oidPart[8] == 8)) { // mcAtcPedestrianDetectorExtraCallPhases, mcAtcPedestrianDetectorCallOverlaps
      if (bDecodeUInt2(&ptrMsg->ucReadPointer, &usValue, errorCode)) {
        if ((usValue < OID[ptrMsg->usObjectRow].oidMin) || (usValue > OID[ptrMsg->usObjectRow].oidMax)) {
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
        if (validate) {
          return (TRUE);
        }
      } else {
        return (FALSE);
      }
    } else {
      if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
        if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
          *errorCode = SNMPERRORBADVALUE;
          return (FALSE);
        }
        if (validate) {
          return (TRUE);
        }
      } else {
        return (FALSE);
      }
    }
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 2: // mcAtcPedestrianDetectorCallPhase
        ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].pedestrianDetectorCallPhase = ucValue;
        break;
      case 3: // mcAtcPedestrianDetectorNoActivity
        ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].pedestrianDetectorNoActivity = ucValue;
        break;
      case 4: // mcAtcPedestrianDetectorMaxPresence
        ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].pedestrianDetectorMaxPresence = ucValue;
        break;
      case 5: // mcAtcPedestrianDetectorErraticCounts
        ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].pedestrianDetectorErraticCounts = ucValue;
        break;
      case 6: // mcAtcPedestrianDetectorOptions
        ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPedestrianDetectorOptions = ucValue;
        break;
      case 7: // mcAtcPedestrianDetectorExtraCallPhases
        ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPedestrianDetectorExtraCallPhases = usValue;
        break;
      case 8: // mcAtcPedestrianDetectorCallOverlaps
        ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPedestrianDetectorCallOverlaps = usValue;
        break;
      case 9: // mcAtc1202PedestrianButtonPushTime
        ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].pedestrianButtonPushTime = ucValue;
        break;
      case 10: // mcAtc1202PedestrianDetectorOptions
        ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].pedestrianDetectorOptions = ucValue;
        break;
      default:
        *errorCode = SNMPERRORNOSUCHNAME;
        return (FALSE);
    }
    if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
      return TRUE;
    }
    if ((OID[ptrMsg->usObjectRow].oidPart[8] == 7) || (OID[ptrMsg->usObjectRow].oidPart[8] == 8)) { // mcAtcPedestrianDetectorExtraCallPhases, mcAtcPedestrianDetectorCallOverlaps
      return bAppendUInt(usValue, ptrResp, sizResp, errorCode);
    } else {
      return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
    }
  }
  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 2: // mcAtcPedestrianDetectorCallPhase
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].pedestrianDetectorCallPhase, ptrResp, sizResp, errorCode);
    case 3: // mcAtcPedestrianDetectorNoActivity
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].pedestrianDetectorNoActivity, ptrResp, sizResp, errorCode);
    case 4: // mcAtcPedestrianDetectorMaxPresence
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].pedestrianDetectorMaxPresence, ptrResp, sizResp, errorCode);
    case 5: // mcAtcPedestrianDetectorErraticCounts
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].pedestrianDetectorErraticCounts, ptrResp, sizResp, errorCode);
    case 6: // mcAtcPedestrianDetectorOptions
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPedestrianDetectorOptions, ptrResp, sizResp, errorCode);
    case 7: // mcAtcPedestrianDetectorExtraCallPhases
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPedestrianDetectorExtraCallPhases, ptrResp, sizResp, errorCode);
    case 8: // mcAtcPedestrianDetectorCallOverlaps
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].mcAtcPedestrianDetectorCallOverlaps, ptrResp, sizResp, errorCode);
    case 9: // mcAtc1202PedestrianButtonPushTime
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].pedestrianButtonPushTime, ptrResp, sizResp, errorCode);
    case 10: // mcAtc1202PedestrianDetectorOptions
      return bAppendUInt(ptrMsg->ptNtcipParameters->atPedestrianDetectorData[ptrMsg->usObjectIndex[0] - 1][ptrMsg->usObjectIndex[1] - 1].pedestrianDetectorOptions, ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_pedDetectorParms()

//*******************************************************************************
//! function for custom serial parameters
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_serialParms(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                       INT8U **ptrResp,        //!< [inout] response buffer
                       INT16U *sizResp,        //!< [inout] response buffer size
                       BOOLEAN validate,       //!< only perform dry-run write if set
                       INT16U *errorCode)      //!< [out] return error code
{
  INT8U ucValue = 0;
  INT16U usValue = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 1:
        if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
          if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if ((ucValue == SERIAL_PROTOCOL_TERMINAL) && (ptrMsg->usObjectIndex[0] != 4)) { // Terminal (3) is only allowed on port 4
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;
      case 2: // mcAtcSerialAddress
        if (bDecodeUInt2(&ptrMsg->ucReadPointer, &usValue, errorCode)) {
          if ((usValue < OID[ptrMsg->usObjectRow].oidMin) || (usValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;

      default:
        if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
          if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;
    }
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 1: // mcAtcSerialProtocol
        ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialProtocol = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialProtocol, ptrResp, sizResp, errorCode);
      case 2: // mcAtcSerialAddress
        ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialAddress = usValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialAddress, ptrResp, sizResp, errorCode);
      case 3: // mcAtcSerialGroupAddress
        ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialGroupAddress = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialGroupAddress, ptrResp, sizResp, errorCode);
      case 4: // mcAtcSerialSpeed
        ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialSpeed = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialSpeed, ptrResp, sizResp, errorCode);
      case 5: // mcAtcSerialParity
        ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialParity = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialParity, ptrResp, sizResp, errorCode);
      case 6: // mcAtcSerialDataBits
        ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialDataBits = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialDataBits, ptrResp, sizResp, errorCode);
      case 7: // mcAtcSerialStopBits
        ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialStopBits = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialStopBits, ptrResp, sizResp, errorCode);
      case 8: // mcAtcSerialFlowControl
        ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialFlowControl = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialFlowControl, ptrResp, sizResp, errorCode);
      case 9: // mcAtcSerialCtsDelay
        ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialCtsDelay = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialCtsDelay, ptrResp, sizResp, errorCode);
      case 10: // mcAtcSerialRtsExtend
        ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialRtsExtend = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialRtsExtend, ptrResp, sizResp, errorCode);
      default:
        *errorCode = SNMPERRORNOSUCHNAME;
        return (FALSE);
    }
  }
  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 1: // mcAtcSerialProtocol
      return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialProtocol, ptrResp, sizResp, errorCode);
    case 2: // mcAtcSerialAddress
      return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialAddress, ptrResp, sizResp, errorCode);
    case 3: // mcAtcSerialGroupAddress
      return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialGroupAddress, ptrResp, sizResp, errorCode);
    case 4: // mcAtcSerialSpeed
      return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialSpeed, ptrResp, sizResp, errorCode);
    case 5: // mcAtcSerialParity
      return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialParity, ptrResp, sizResp, errorCode);
    case 6: // mcAtcSerialDataBits
      return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialDataBits, ptrResp, sizResp, errorCode);
    case 7: // mcAtcSerialStopBits
      return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialStopBits, ptrResp, sizResp, errorCode);
    case 8: // mcAtcSerialFlowControl
      return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialFlowControl, ptrResp, sizResp, errorCode);
    case 9: // mcAtcSerialCtsDelay
      return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialCtsDelay, ptrResp, sizResp, errorCode);
    case 10: // mcAtcSerialRtsExtend
      return bAppendUInt(ptrMsg->ptNtcipParameters->serialPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcSerialRtsExtend, ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_serialParms()

//*******************************************************************************
//! function for custom Ethernet parameters
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_ethernetParms(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                         INT8U **ptrResp,        //!< [inout] response buffer
                         INT16U *sizResp,        //!< [inout] response buffer size
                         BOOLEAN validate,       //!< only perform dry-run write if set
                         INT16U *errorCode)      //!< [out] return error code
{
  INT8U ucValue = 0;
  INT16U usValue = 0;
  INT32U ulValue = 0;
  INT8U anOCTETvalue[SIZE_HOSTNAME]; // accommodate largest octet string handled by this function
  INT16U u16DataSize = 0;

  memset(anOCTETvalue, 0, sizeof(anOCTETvalue));

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 5:  // mcAtcEthernetDhcpMode
      case 9:  // mcAtcEthernetIpv6cidr
      case 14: // mcAtcEthernetNtcipMode
      case 16: // mcAtcEthernetAB3418Mode
      case 18: // mcAtcEthernetAB3418GroupAddr
      case 22: // mcAtcEthernetFhpCity
        if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
          if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;

      case 13: // mcAtcEthernetNtcipPort
      case 15: // mcAtcEthernetAB3418Port
      case 17: // mcAtcEthernetAB3418Addr
      case 19: // mcAtcEthernetP2pPort
      case 20: // mcAtcEthernetFhpPort
      case 21: // mcAtcEthernetFhpAddr
        if (bDecodeUInt2(&ptrMsg->ucReadPointer, &usValue, errorCode)) {
          if ((usValue < OID[ptrMsg->usObjectRow].oidMin) || (usValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;

      case 1: // mcAtcEthernetIpAddr
      case 2: // mcAtcEthernetNetmask
      case 3: // mcAtcEthernetGateway
      case 4: // mcAtcEthernetDnsServer
      case 6: // mcAtcEthernetDhcpStart
      case 7: // mcAtcEthernetDhcpEnd
        if (bDecodeGaugeValue(&ptrMsg->ucReadPointer, &ulValue, &u16DataSize, errorCode)) {
          if ((ulValue < (INT32U)OID[ptrMsg->usObjectRow].oidMin) || (ulValue > (INT32U)OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;

      case 8:  // mcAtcEthernetIpv6Addr
      case 10: // mcAtcEthernetIpv6gateway
      case 11: // mcAtcEthernetIpv6dnsServer
        ptrMsg->usCurrentDataSize = SIZE_IPv6_ADDRESS;
        if (bDecodeOctetValue(&ptrMsg->ucReadPointer, anOCTETvalue, &ptrMsg->usCurrentDataSize, errorCode)) {
          if (ptrMsg->usCurrentDataSize != SIZE_IPv6_ADDRESS) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;

      case 12: // mcAtcEthernetHostname
        ptrMsg->usCurrentDataSize = SIZE_HOSTNAME;
        if (bDecodeOctetValue(&ptrMsg->ucReadPointer, anOCTETvalue, &ptrMsg->usCurrentDataSize, errorCode)) {
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;
      case 23: // u8McAtcEthernetFhpResponseForward
        ptrMsg->usCurrentDataSize = MAX_FHP_FORWARDS;
        if (bDecodeOctetValue(&ptrMsg->ucReadPointer, anOCTETvalue, &ptrMsg->usCurrentDataSize, errorCode)) {
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;
      default:
        break;
    }
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 1: // mcAtcEthernetIpAddr
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpAddr = ulValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendGaugeValue(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpAddr, ptrResp, sizResp, errorCode);
      case 2: // mcAtcEthernetNetmask
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetNetmask = ulValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendGaugeValue(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetNetmask, ptrResp, sizResp, errorCode);
      case 3: // mcAtcEthernetNetmask
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetGateway = ulValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendGaugeValue(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetGateway, ptrResp, sizResp, errorCode);
      case 4: // mcAtcEthernetNetmask
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetDnsServer = ulValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendGaugeValue(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetDnsServer, ptrResp, sizResp, errorCode);
      case 5: // mcAtcEthernetDhcpMode
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetDhcpMode = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetDhcpMode, ptrResp, sizResp, errorCode);
      case 6: // mcAtcEthernetDhcpStart
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetDhcpStart = ulValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendGaugeValue(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetDhcpStart, ptrResp, sizResp, errorCode);
      case 7: // mcAtcEthernetDhcpEnd
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetDhcpEnd = ulValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendGaugeValue(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetDhcpEnd, ptrResp, sizResp, errorCode);
      case 8: // mcAtcEthernetIpv6Addr
        memcpy(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpv6Addr, anOCTETvalue, SIZE_IPv6_ADDRESS);
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        ptrMsg->usCurrentDataSize = SIZE_IPv6_ADDRESS;
        return bAppendOctet(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpv6Addr, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      case 9: // mcAtcEthernetIpv6cidr
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpv6cidr = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpv6cidr, ptrResp, sizResp, errorCode);
      case 10: // mcAtcEthernetIpv6gateway
        memcpy(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpv6gateway, anOCTETvalue, SIZE_IPv6_ADDRESS);
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        ptrMsg->usCurrentDataSize = SIZE_IPv6_ADDRESS;
        return bAppendOctet(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpv6gateway, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      case 11: // mcAtcEthernetIpv6dnsServer
        memcpy(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpv6dnsServer, anOCTETvalue, SIZE_IPv6_ADDRESS);
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        ptrMsg->usCurrentDataSize = SIZE_IPv6_ADDRESS;
        return bAppendOctet(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpv6dnsServer, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      case 12: // mcAtcEthernetHostname
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetHostname[0] = 0;
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetHostname[1] = ptrMsg->usCurrentDataSize;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        memcpy(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetHostname + 2, anOCTETvalue, SIZE_HOSTNAME);
        return bAppendOctet(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetHostname + 2, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      case 13: // mcAtcEthernetNtcipPort
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetNtcipPort = usValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetNtcipPort, ptrResp, sizResp, errorCode);
      case 14: // mcAtcEthernetNtcipMode
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetNtcipMode = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetNtcipMode, ptrResp, sizResp, errorCode);
      case 15: // mcAtcEthernetAB3418Port
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetAB3418Port = usValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetAB3418Port, ptrResp, sizResp, errorCode);
      case 16: // mcAtcEthernetAB3418Mode
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetAB3418Mode = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetAB3418Mode, ptrResp, sizResp, errorCode);
      case 17: // mcAtcEthernetAB3418Addr
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetAB3418Addr = usValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetAB3418Addr, ptrResp, sizResp, errorCode);
      case 18: // mcAtcEthernetAB3418GroupAddr
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetAB3418GroupAddr = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetAB3418GroupAddr, ptrResp, sizResp, errorCode);
      case 19: // mcAtcEthernetP2pPort
               // Note: there is currently only a single P2P port number that is used with both ethernet ports. It is not stored in the ethernet param structure. Ignore the index.
        ptrMsg->ptNtcipParameters->peerPortNumber = usValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->peerPortNumber, ptrResp, sizResp, errorCode);
      case 20: // mcAtcEthernetFhpPort
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpPort = usValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpPort, ptrResp, sizResp, errorCode);
      case 21: // mcAtcEthernetFhpAddr
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpAddr = usValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpAddr, ptrResp, sizResp, errorCode);
      case 22: // mcAtcEthernetFhpCity
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpCity = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpCity, ptrResp, sizResp, errorCode);
      case 23: // u8McAtcEthernetFhpResponseForward
        ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].u8McAtcEthernetFhpResponseForward = u8InternalOctet1ByteArray(anOCTETvalue, (INT8U)(ptrMsg->usCurrentDataSize), MAX_FHP_FORWARDS);
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decoe mode.
          return TRUE;
        }
        ptrMsg->usCurrentDataSize = (INT16U)(u8BitArray2InternalOctet(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].u8McAtcEthernetFhpResponseForward, anOCTETvalue, MAX_FHP_FORWARDS));
        return bAppendOctet(&(anOCTETvalue[LOCAL_OCTET_HEADER_SIZE]), ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      default:
        *errorCode = SNMPERRORNOSUCHNAME;
        return (FALSE);
    }
  }
  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 1: // mcAtcEthernetIpAddr
      return bAppendGaugeValue(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpAddr, ptrResp, sizResp, errorCode);
    case 2: // mcAtcEthernetNetmask
      return bAppendGaugeValue(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetNetmask, ptrResp, sizResp, errorCode);
    case 3: // mcAtcEthernetNetmask
      return bAppendGaugeValue(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetGateway, ptrResp, sizResp, errorCode);
    case 4: // mcAtcEthernetNetmask
      return bAppendGaugeValue(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetDnsServer, ptrResp, sizResp, errorCode);
    case 5: // mcAtcEthernetDhcpMode
      return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetDhcpMode, ptrResp, sizResp, errorCode);
    case 6: // mcAtcEthernetDhcpStart
      return bAppendGaugeValue(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetDhcpStart, ptrResp, sizResp, errorCode);
    case 7: // mcAtcEthernetDhcpEnd
      return bAppendGaugeValue(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetDhcpEnd, ptrResp, sizResp, errorCode);
    case 8: // mcAtcEthernetIpv6Addr
      ptrMsg->usCurrentDataSize = SIZE_IPv6_ADDRESS;
      return bAppendOctet(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpv6Addr, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    case 9: // mcAtcEthernetIpv6cidr
      return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpv6cidr, ptrResp, sizResp, errorCode);
    case 10: // mcAtcEthernetIpv6gateway
      ptrMsg->usCurrentDataSize = SIZE_IPv6_ADDRESS;
      return bAppendOctet(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpv6gateway, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    case 11: // mcAtcEthernetIpv6dnsServer
      ptrMsg->usCurrentDataSize = SIZE_IPv6_ADDRESS;
      return bAppendOctet(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetIpv6dnsServer, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    case 12: // mcAtcEthernetHostname
      ptrMsg->usCurrentDataSize = ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetHostname[1];
      return bAppendOctet(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetHostname + 2, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    case 13: // mcAtcEthernetNtcipPort
      return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetNtcipPort, ptrResp, sizResp, errorCode);
    case 14: // mcAtcEthernetNtcipMode
      return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetNtcipMode, ptrResp, sizResp, errorCode);
    case 15: // mcAtcEthernetAB3418Port
      return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetAB3418Port, ptrResp, sizResp, errorCode);
    case 16: // mcAtcEthernetAB3418Mode
      return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetAB3418Mode, ptrResp, sizResp, errorCode);
    case 17: // mcAtcEthernetAB3418Addr
      return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetAB3418Addr, ptrResp, sizResp, errorCode);
    case 18: // mcAtcEthernetAB3418GroupAddr
      return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetAB3418GroupAddr, ptrResp, sizResp, errorCode);
    case 19: // mcAtcEthernetP2pPort
             // Note: there is currently only a single P2P port number that is used with both ethernet ports. It is not stored in the ethernet param structure. Ignore the index.
      return bAppendUInt(ptrMsg->ptNtcipParameters->peerPortNumber, ptrResp, sizResp, errorCode);
    case 20: // mcAtcEthernetFhpPort
      return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpPort, ptrResp, sizResp, errorCode);
    case 21: // mcAtcEthernetFhpAddr
      return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpAddr, ptrResp, sizResp, errorCode);
    case 22: // mcAtcEthernetFhpCity
      return bAppendUInt(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpCity, ptrResp, sizResp, errorCode);
    case 23: // u8McAtcEthernetFhpResponseForward
      ptrMsg->usCurrentDataSize = (INT16U)(u8BitArray2InternalOctet(ptrMsg->ptNtcipParameters->enetPorts[ptrMsg->usObjectIndex[0] - 1].u8McAtcEthernetFhpResponseForward, anOCTETvalue, MAX_FHP_FORWARDS));
      return bAppendOctet(&(anOCTETvalue[LOCAL_OCTET_HEADER_SIZE]), ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_ethernetParms()

/*************************************************************************************************/
/*  Name       : bFnEthernetFhpForwards                                                          */
/*                                                                                               */
/*  Description: Handle the Ethernet Foothill Protocol response forward list.                    */
/*************************************************************************************************/
BOOLEAN bFnEthernetFhpForwards(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                               INT8U **ptrResp,        //!< [inout] response buffer
                               INT16U *sizResp,        //!< [inout] response buffer size
                               BOOLEAN validate,       //!< only perform dry-run write if set
                               INT16U *errorCode)      //!< [out] return error code
{
  INT16U u16Value = 0;
  INT32U u32Value = 0;
  INT16U u16DataSize = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    switch (OID[ptrMsg->usObjectRow].oidPart[9]) {
      case 2: // mcAtcEthernetFhpForwardingIpAddress
        if (bDecodeGaugeValue(&ptrMsg->ucReadPointer, &u32Value, &u16DataSize, errorCode)) {
          if ((u32Value < (INT32U)OID[ptrMsg->usObjectRow].oidMin) || (u32Value > (INT32U)OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return FALSE;
          }
          if (validate) {
            return TRUE;
          }
        } else {
          return FALSE;
        }
        ptrMsg->ptNtcipParameters->mcAtcEthernetFhpForwarding[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpForwardingIpAddress = u32Value;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        break;
      case 3: // mcAtcEthernetFhpForwardingPort
        if (bDecodeUInt2(&ptrMsg->ucReadPointer, &u16Value, errorCode)) {
          if ((u16Value < (INT16U)(OID[ptrMsg->usObjectRow].oidMin)) || (u16Value > (INT16U)(OID[ptrMsg->usObjectRow].oidMax))) {
            *errorCode = SNMPERRORBADVALUE;
            return FALSE;
          }
          if (validate) {
            return TRUE;
          }
        } else {
          return FALSE;
        }
        ptrMsg->ptNtcipParameters->mcAtcEthernetFhpForwarding[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpForwardingPort = u16Value;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcEthernetFhpForwarding[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpForwardingPort, ptrResp, sizResp, errorCode);
      default:
        *errorCode = SNMPERRORNOSUCHNAME;
        return FALSE;
    }
  }
  switch (OID[ptrMsg->usObjectRow].oidPart[9]) {
    case 2: // mcAtcEthernetFhpForwardingIpAddress
      return bAppendGaugeValue(ptrMsg->ptNtcipParameters->mcAtcEthernetFhpForwarding[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpForwardingIpAddress, ptrResp, sizResp, errorCode);
    case 3: // mcAtcEthernetFhpForwardingPort
      return bAppendUInt(ptrMsg->ptNtcipParameters->mcAtcEthernetFhpForwarding[ptrMsg->usObjectIndex[0] - 1].mcAtcEthernetFhpForwardingPort, ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return FALSE;
  }
}

//*******************************************************************************
//! function for ntp parameters
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_ntpParms(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                    INT8U **ptrResp,        //!< [inout] response buffer
                    INT16U *sizResp,        //!< [inout] response buffer size
                    BOOLEAN validate,       //!< only perform dry-run write if set
                    INT16U *errorCode)      //!< [out] return error code
{
  INT8U anOCTETvalue[SIZE_IPv6_ADDRESS]; // accommodate largest octet string handled by this function

  memset(anOCTETvalue, 0, sizeof(anOCTETvalue));

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    switch (OID[ptrMsg->usObjectRow].oidPart[6]) {
      case 2: // mcAtcNtpIpv6Addr
        ptrMsg->usCurrentDataSize = SIZE_IPv6_ADDRESS;
        if (bDecodeOctetValue(&ptrMsg->ucReadPointer, anOCTETvalue, &ptrMsg->usCurrentDataSize, errorCode)) {
          if (ptrMsg->usCurrentDataSize != SIZE_IPv6_ADDRESS) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;
      default:
        break;
    }
    switch (OID[ptrMsg->usObjectRow].oidPart[6]) {
      case 2: // mcAtcNtpIpv6Addr
        memcpy(ptrMsg->ptNtcipParameters->timeSync.mcAtcNtpIpv6Addr, anOCTETvalue, SIZE_IPv6_ADDRESS);
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        ptrMsg->usCurrentDataSize = SIZE_IPv6_ADDRESS;
        return bAppendOctet(ptrMsg->ptNtcipParameters->timeSync.mcAtcNtpIpv6Addr, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
      default:
        *errorCode = SNMPERRORNOSUCHNAME;
        return (FALSE);
    }
  }

  switch (OID[ptrMsg->usObjectRow].oidPart[6]) {
    case 2: // mcAtcNtpIpv6Addr
      ptrMsg->usCurrentDataSize = SIZE_IPv6_ADDRESS;
      return bAppendOctet(ptrMsg->ptNtcipParameters->timeSync.mcAtcNtpIpv6Addr, ptrResp, sizResp, ptrMsg->usCurrentDataSize, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_ntpParms()

/*************************************************************************************************/
/*  Name       : fn_spatData()                                                                   */
/*                                                                                               */
/*  Description: return the mib objects for SPaT. This work is in progress.                      */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN fn_spatData(TYPE_COMMS_MSG *ptMsg,                     //!< [inout] message structure holding received message
                    INT8U **pu8Resp,                           //!< [inout] response buffer
                    INT16U *pu16SizeResp,                      //!< [inout] response buffer size
                    BOOLEAN bValidate __attribute__((unused)), //!< only perform dry-run write if set
                    INT16U *pu16ErrorCode)                     //!< [out] return error code
{
  if (ptMsg->boIsWriteTheValue) {
    *pu16ErrorCode = SNMPERRORREADONLY;
    return (FALSE);
  }

  *pu16ErrorCode = SNMPERRORNOERROR;

  switch (OID[ptMsg->usObjectRow].oidPart[7]) { // index 7 for 8th OID table byte (1 - 10)
    case 5:                                     // spatPhaseTimeToChangeTable
      if (OID[ptMsg->usObjectRow].oidPart[8] == 1) {
        switch (OID[ptMsg->usObjectRow].oidPart[9]) { // index 6 for 7th OID table byte
          case 2:                                     // spatVehMinTimeToChange
            return bAppendUInt(psNtcipStatus->spatBroadcastMsg.spatTimeToChangeTable[ptMsg->usObjectIndex[0] - 1].vehTimeToChange.min, pu8Resp, pu16SizeResp, pu16ErrorCode);
          case 3: // spatVehMaxTimeToChange
            return bAppendUInt(psNtcipStatus->spatBroadcastMsg.spatTimeToChangeTable[ptMsg->usObjectIndex[0] - 1].vehTimeToChange.max, pu8Resp, pu16SizeResp, pu16ErrorCode);
          case 4: // spatPedMinTimeToChange
            return bAppendUInt(psNtcipStatus->spatBroadcastMsg.spatTimeToChangeTable[ptMsg->usObjectIndex[0] - 1].pedTimeToChange.min, pu8Resp, pu16SizeResp, pu16ErrorCode);
          case 5: // spatPedMaxTimeToChange
            return bAppendUInt(psNtcipStatus->spatBroadcastMsg.spatTimeToChangeTable[ptMsg->usObjectIndex[0] - 1].pedTimeToChange.max, pu8Resp, pu16SizeResp, pu16ErrorCode);
          default: // do nothing
            break;
        }
      }
      break;
    case 6: // spatOvlpTimeToChangeTable
      if (OID[ptMsg->usObjectRow].oidPart[8] == 1) {
        switch (OID[ptMsg->usObjectRow].oidPart[9]) {
          case 2: // spatOvlpMinTimeToChange
            return bAppendUInt(psNtcipStatus->spatBroadcastMsg.spatTimeToChangeTable[ptMsg->usObjectIndex[0] - 1].ovlpTimeToChange.min, pu8Resp, pu16SizeResp, pu16ErrorCode);
          case 3: // spatOvlpMaxTimeToChange
            return bAppendUInt(psNtcipStatus->spatBroadcastMsg.spatTimeToChangeTable[ptMsg->usObjectIndex[0] - 1].ovlpTimeToChange.max, pu8Resp, pu16SizeResp, pu16ErrorCode);
          default: // do nothing
            break;
        }
      }
      break;

    case 7:                                                                                                             // spatIntersectionStatus
      return bAppendUInt(psNtcipStatus->spatBroadcastMsg.spatIntersectionStatus, pu8Resp, pu16SizeResp, pu16ErrorCode); //?? better to use std MACRO?

    case 8:                                                                                                                  // spatDiscontinuousChangeFlag
      return bAppendUInt(psNtcipStatus->spatBroadcastMsg.spatDiscontinuousChangeFlag, pu8Resp, pu16SizeResp, pu16ErrorCode); //?? better to use std MACRO?

    case 9:                                                                                                            // spatMessageSeqCounter
      return bAppendUInt(psNtcipStatus->spatBroadcastMsg.spatMessageSeqCounter, pu8Resp, pu16SizeResp, pu16ErrorCode); //?? better to use std MACRO?
    default:
      break;
  }

  *pu16ErrorCode = SNMPERRORNOSUCHNAME;
  return (FALSE);
} // end fn_spatData()

//*******************************************************************************
//! function for TSP Control ETA
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_priorityControlEta(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                              INT8U **ptrResp,                          //!< [inout] response buffer
                              INT16U *sizResp,                          //!< [inout] response buffer size
                              BOOLEAN __attribute__((unused)) validate, //!< not used
                              INT16U *pu16ErrorCode)                    //!< [out] return error code
{
  INT8U u8Idx = ptrMsg->usObjectIndex[0] - 1;
  INT8U u8Value = 0;

  *pu16ErrorCode = SNMPERRORNOERROR; // expect no errors
  // When the ETA is set, also mark the ETA as updated
  if (ptrMsg->boIsWriteTheValue) {
    // This is a write, set the value
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &u8Value, pu16ErrorCode)) {
      // We have a value, set it
      if (s8SetIVar1Byte_r(IVAR_ID__CONTROL_PRIORITY_ETA_1 + u8Idx, u8Value, psATCsys->eCaptureFlag, &psTrafficIn->tIVars, &psTrafficIn->tIVarsTick) == 0) {
        pthread_mutex_lock(&(psATCsys->asInputImages[INPUT_SIGNALS_NTCIP].mInputImageMutex));
        psATCsys->asInputImages[INPUT_SIGNALS_NTCIP].abInputSignals[IN_CONTROL_PRIORITY_ETA_UPDATED_1 + u8Idx] = TRUE;
        pthread_mutex_unlock(&(psATCsys->asInputImages[INPUT_SIGNALS_NTCIP].mInputImageMutex));
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
      } else {
        *pu16ErrorCode = SNMPERRORGENERALERROR;
      }
    }
  } else {
    if (s8GetIVar1Byte_r(IVAR_ID__CONTROL_PRIORITY_ETA_1 + u8Idx, &u8Value, psATCsys->eCaptureFlag, &psTrafficIn->tIVars, &psTrafficIn->tIVarsTick)) {
      *pu16ErrorCode = SNMPERRORGENERALERROR;
    }
  }
  return bAppendUInt(u8Value, ptrResp, sizResp, pu16ErrorCode);
}

//*******************************************************************************
//! function for Phase Control Red Extension
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_phaseControlRedExtension(TYPE_COMMS_MSG *ptrMsg,                   //!< [inout] message structure holding received message
                                    INT8U **ptrResp,                          //!< [inout] response buffer
                                    INT16U *sizResp,                          //!< [inout] response buffer size
                                    BOOLEAN __attribute__((unused)) validate, //!< not used
                                    INT16U *pu16ErrorCode)                    //!< [out] return error code
{
  INT8U u8Idx = ptrMsg->usObjectIndex[0] - 1;
  INT8U u8Value = 0;

  *pu16ErrorCode = SNMPERRORNOERROR; // expect no errors
  // When the Red Extension is set, also mark the Red Extension as updated
  if (ptrMsg->boIsWriteTheValue) {
    // This is a write, set the value
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &u8Value, pu16ErrorCode)) {
      // We have a value, set it
      if (s8SetIVar1Byte_r(IVAR_ID__CONTROL_RED_EXTEND_1 + u8Idx, u8Value, psATCsys->eCaptureFlag, &psTrafficIn->tIVars, &psTrafficIn->tIVarsTick) == 0) {
        pthread_mutex_lock(&(psATCsys->asInputImages[INPUT_SIGNALS_NTCIP].mInputImageMutex));
        // Indicate that the dynamic Red Extension value has been updated
        psATCsys->asInputImages[INPUT_SIGNALS_NTCIP].abInputSignals[IN_CONTROL_RED_EXTENSION_UPDATED_1 + u8Idx] = TRUE;
        pthread_mutex_unlock(&(psATCsys->asInputImages[INPUT_SIGNALS_NTCIP].mInputImageMutex));
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
      } else {
        *pu16ErrorCode = SNMPERRORGENERALERROR;
      }
    }
  } else {
    if (s8GetIVar1Byte_r(IVAR_ID__CONTROL_RED_EXTEND_1 + u8Idx, &u8Value, psATCsys->eCaptureFlag, &psTrafficIn->tIVars, &psTrafficIn->tIVarsTick)) {
      *pu16ErrorCode = SNMPERRORGENERALERROR;
    }
  }
  return bAppendUInt(u8Value, ptrResp, sizResp, pu16ErrorCode);
}

//*******************************************************************************
//! function for handling peer device table
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_peerDevices(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                       INT8U **ptrResp,        //!< [inout] response buffer
                       INT16U *sizResp,        //!< [inout] response buffer size
                       BOOLEAN validate,       //!< only perform dry-run write if set
                       INT16U *errorCode)      //!< [out] return error code
{
  INT8U ucValue = 0;
  INT16U usValue = 0;
  INT32U ulValue = 0;
  INT16U idx1 = ptrMsg->usObjectIndex[0] - 1;
  INT16U u16DataSize = 0;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {

      case 2: // mcAtcP2pPeerIpv4Address
      case 3: // mcAtcP2pPeerSystemId
        if (bDecodeGaugeValue(&ptrMsg->ucReadPointer, &ulValue, &u16DataSize, errorCode)) {
          if ((ulValue < (INT32U)OID[ptrMsg->usObjectRow].oidMin) || (ulValue > (INT32U)OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;

      case 4: // mcAtcP2pPeerPort
        if (bDecodeUInt2(&ptrMsg->ucReadPointer, &usValue, errorCode)) {
          if ((usValue < OID[ptrMsg->usObjectRow].oidMin) || (usValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;

      case 5: // mcAtcP2pPeerMessageTimeout
      case 6: // mcAtcP2pPeerRetries
      case 7: // mcAtcP2pPeerHeartbeatTime
        if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
          if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;
      default:
        break;
    }

    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 2: // mcAtcP2pPeerIpv4Address
        *((INT32U *)(ptrMsg->ptNtcipParameters->menuPeerConfigs[idx1].ipAddress)) = ulValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendGaugeValue(ulValue, ptrResp, sizResp, errorCode);
      case 3: // mcAtcP2pPeerSystemId
        ptrMsg->ptNtcipParameters->menuPeerConfigs[idx1].systemID = ulValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendGaugeValue(ulValue, ptrResp, sizResp, errorCode);
      case 4: // mcAtcP2pPeerPort
        ptrMsg->ptNtcipParameters->menuPeerConfigs[idx1].port = usValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(usValue, ptrResp, sizResp, errorCode);
      case 5: // mcAtcP2pPeerMessageTimeout
        ptrMsg->ptNtcipParameters->menuPeerConfigs[idx1].messageTimeout = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      case 6: // mcAtcP2pPeerRetries
        ptrMsg->ptNtcipParameters->menuPeerConfigs[idx1].retries = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      case 7: // mcAtcP2pPeerHeartbeatTime
        ptrMsg->ptNtcipParameters->menuPeerConfigs[idx1].heartbeatTime = ucValue;
        if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
          return TRUE;
        }
        return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
      default:
        *errorCode = SNMPERRORNOSUCHNAME;
        return (FALSE);
    }
  }

  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 2: // mcAtcP2pPeerIpv4Address
      return bAppendGaugeValue(*((INT32U *)(ptrMsg->ptNtcipParameters->menuPeerConfigs[idx1].ipAddress)), ptrResp, sizResp, errorCode);
    case 3: // mcAtcP2pPeerSystemId
      return bAppendGaugeValue(ptrMsg->ptNtcipParameters->menuPeerConfigs[idx1].systemID, ptrResp, sizResp, errorCode);
    case 4: // mcAtcP2pPeerPort
      return bAppendUInt(ptrMsg->ptNtcipParameters->menuPeerConfigs[idx1].port, ptrResp, sizResp, errorCode);
    case 5: // mcAtcP2pPeerMessageTimeout
      return bAppendUInt(ptrMsg->ptNtcipParameters->menuPeerConfigs[idx1].messageTimeout, ptrResp, sizResp, errorCode);
    case 6: // mcAtcP2pPeerRetries
      return bAppendUInt(ptrMsg->ptNtcipParameters->menuPeerConfigs[idx1].retries, ptrResp, sizResp, errorCode);
    case 7: // mcAtcP2pPeerHeartbeatTime
      return bAppendUInt(ptrMsg->ptNtcipParameters->menuPeerConfigs[idx1].heartbeatTime, ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_peerDevices()

//*******************************************************************************
//! function for handling peer function table
//! @return       TRUE if no error <br>
//!               FALSE if error (error code in usErrorCode)
//*******************************************************************************
BOOLEAN fn_peerFunctions(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                         INT8U **ptrResp,        //!< [inout] response buffer
                         INT16U *sizResp,        //!< [inout] response buffer size
                         BOOLEAN validate,       //!< only perform dry-run write if set
                         INT16U *errorCode)      //!< [out] return error code
{
  INT8U ucValue = 0;
  INT16U idx1 = ptrMsg->usObjectIndex[0] - 1;

  *errorCode = SNMPERRORNOERROR;
  if (ptrMsg->boIsWriteTheValue) {
    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {

      case 2: // mcAtcP2pFunctionDeviceNumber
      case 3: // mcAtcP2pFunctionRemoteFunction
      case 4: // mcAtcP2pFunctionRemoteFunctionIndex
      case 5: // mcAtcP2pFunctionLocalFunction
      case 6: // mcAtcP2pFunctionLocalFunctionIndex
      case 7: // mcAtcP2pFunctionDefaultState
        if (bDecodeUInt1(&ptrMsg->ucReadPointer, &ucValue, errorCode)) {
          if ((ucValue < OID[ptrMsg->usObjectRow].oidMin) || (ucValue > OID[ptrMsg->usObjectRow].oidMax)) {
            *errorCode = SNMPERRORBADVALUE;
            return (FALSE);
          }
          if (validate) {
            return (TRUE);
          }
        } else {
          return (FALSE);
        }
        break;
      default:
        break;
    }

    switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
      case 2: // mcAtcP2pFunctionDeviceNumber
        ptrMsg->ptNtcipParameters->menuPeerFunctions[idx1].peerIndex = ucValue;
        break;
      case 3: // mcAtcP2pFunctionRemoteFunction
        ptrMsg->ptNtcipParameters->menuPeerFunctions[idx1].peerFunc = ucValue;
        break;
      case 4: // mcAtcP2pFunctionRemoteFunctionIndex
        ptrMsg->ptNtcipParameters->menuPeerFunctions[idx1].peerFuncIdx = ucValue;
        break;
      case 5: // mcAtcP2pFunctionLocalFunction
        ptrMsg->ptNtcipParameters->menuPeerFunctions[idx1].localFunc = ucValue;
        break;
      case 6: // mcAtcP2pFunctionLocalFunctionIndex
        ptrMsg->ptNtcipParameters->menuPeerFunctions[idx1].localFuncIdx = ucValue;
        break;
      case 7: // mcAtcP2pFunctionDefaultState
        ptrMsg->ptNtcipParameters->menuPeerFunctions[idx1].defaultState = ucValue;
        break;
      default:
        *errorCode = SNMPERRORNOSUCHNAME;
        return (FALSE);
    }

    if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode.
      return TRUE;
    }
    return bAppendUInt(ucValue, ptrResp, sizResp, errorCode);
  }

  switch (OID[ptrMsg->usObjectRow].oidPart[8]) {
    case 2: // mcAtcP2pFunctionDeviceNumber
      return bAppendUInt(ptrMsg->ptNtcipParameters->menuPeerFunctions[idx1].peerIndex, ptrResp, sizResp, errorCode);
    case 3: // mcAtcP2pFunctionRemoteFunction
      return bAppendUInt(ptrMsg->ptNtcipParameters->menuPeerFunctions[idx1].peerFunc, ptrResp, sizResp, errorCode);
    case 4: // mcAtcP2pFunctionRemoteFunctionIndex
      return bAppendUInt(ptrMsg->ptNtcipParameters->menuPeerFunctions[idx1].peerFuncIdx, ptrResp, sizResp, errorCode);
    case 5: // mcAtcP2pFunctionLocalFunction
      return bAppendUInt(ptrMsg->ptNtcipParameters->menuPeerFunctions[idx1].localFunc, ptrResp, sizResp, errorCode);
    case 6: // mcAtcP2pFunctionLocalFunctionIndex
      return bAppendUInt(ptrMsg->ptNtcipParameters->menuPeerFunctions[idx1].localFuncIdx, ptrResp, sizResp, errorCode);
    case 7: // mcAtcP2pFunctionDefaultState
      return bAppendUInt(ptrMsg->ptNtcipParameters->menuPeerFunctions[idx1].defaultState, ptrResp, sizResp, errorCode);
    default:
      *errorCode = SNMPERRORNOSUCHNAME;
      return (FALSE);
  }
} // end fn_peerFunctions()

/*************************************************************************************************/
/*  Name       : fn_security()                                                                   */
/*                                                                                               */
/*  Description: Function for security parameters                                                */
/*                                                                                               */
/*************************************************************************************************/
BOOLEAN fn_security(TYPE_COMMS_MSG *ptMsg, INT8U **ppu8Resp, INT16U *pu16SizeResp, BOOLEAN bValidate, INT16U *pu16ErrorCode)
{
  const TYPE_OIDTABLE *ptOidRow = OID + ptMsg->usObjectRow;
  TYPE_ACCESS_FUNCTION_DATA tAccessFnData = {bValidate, ppu8Resp, pu16SizeResp, pu16ErrorCode, ptMsg, ptOidRow};
  TYPE_SECURITY *ptSecurity = &(ptMsg->ptNtcipParameters->tMcAtcSecurity);
  INT16U u16Idx = ptMsg->usObjectIndex[0] - 1;
  INT8U *pcOctet = NULL;
  INT16U u16Size = 0;
  BOOLEAN bDone = FALSE;
  INT8U acOctetValue[SIZE_OCTET_STRING_CONFIG + LOCAL_OCTET_HEADER_SIZE];

  memset(acOctetValue, 0, sizeof(acOctetValue));

  *pu16ErrorCode = SNMPERRORNOERROR;

  switch (ptOidRow->oidPart[7]) {
    case 1: return bProcessU8Object(&tAccessFnData, &(ptSecurity->u8McAtcSecUserAuthTries));
    case 2: return bProcessU8Object(&tAccessFnData, &(ptSecurity->u8McAtcSecUserAuthTimeWait));
    case 3: return bProcessU8Object(&tAccessFnData, &(ptSecurity->u8McAtcSecUserAuthTriesBlock));
    case 4: return bProcessU8Object(&tAccessFnData, &(ptSecurity->u8McAtcSecUserSessionTimeout));
    // case 5: is mcAtcSecUserMaxUsers. This object is processed by the actionMax() action function.
    case 6:
      if (ptOidRow->oidPart[8] == 1) {

        switch (ptOidRow->oidPart[9]) {
          case 2: // mcAtcSecUserName
            if (ptMsg->boIsWriteTheValue) {
              return bSetOctetObject(&tAccessFnData, ptOidRow->oidMax, 0, ptSecurity->atMcAtcSecUsers[u16Idx].au8McAtcSecUserName);
            }
            ptMsg->usCurrentDataSize = strlen((const char *)ptSecurity->atMcAtcSecUsers[u16Idx].au8McAtcSecUserName);
            return bAppendOctet(ptSecurity->atMcAtcSecUsers[u16Idx].au8McAtcSecUserName, ppu8Resp, pu16SizeResp, ptMsg->usCurrentDataSize, pu16ErrorCode);
          case 3: // mcAtcSecUserKey
            /* This object is documented as -ACCESS not-accessible - in the mib file and it is configured as ACCESS_NONE in the OID table.
            So ntcip returns "not such name" when it is accessed throught snmp. This code is only for allowing read/write access for MCB files.*/
            if (ptMsg->boIsWriteTheValue) {
              return bSetOctetObject(&tAccessFnData, ptOidRow->oidMax, SIZE_USERKEY, ptSecurity->atMcAtcSecUsers[u16Idx].au8McAtcSecUserKey);
            }
            ptMsg->usCurrentDataSize = SIZE_USERKEY;
            return bAppendOctet(ptSecurity->atMcAtcSecUsers[u16Idx].au8McAtcSecUserKey, ppu8Resp, pu16SizeResp, ptMsg->usCurrentDataSize, pu16ErrorCode);
          case 4: // mcAtcSecUserECabinetStatus. we need saving it coded as octet image.
            if (ptMsg->boIsWriteTheValue) {
              bDone = bSetOctetObject(&tAccessFnData, SIZE_OCTET_STRING_CONFIG + LOCAL_OCTET_HEADER_SIZE, 0, acOctetValue);
              vSetInternalOctetImage(ptSecurity->atMcAtcSecUsers[u16Idx].au8McAtcSecUserECabinetStatus, SIZE_OCTET_STRING_CONFIG + LOCAL_OCTET_HEADER_SIZE, ptMsg->usCurrentDataSize, acOctetValue);
              return bDone;
            }
            // Get the octet value
            u16Size = u16GetInternalOctetLength(ptSecurity->atMcAtcSecUsers[u16Idx].au8McAtcSecUserECabinetStatus);
            pcOctet = ptSecurity->atMcAtcSecUsers[u16Idx].au8McAtcSecUserECabinetStatus + LOCAL_OCTET_HEADER_SIZE;
            ptMsg->usCurrentDataSize = u16Size;
            return bAppendOctet(pcOctet, ppu8Resp, pu16SizeResp, ptMsg->usCurrentDataSize, pu16ErrorCode);

          default: break;
        }
      }
      break;
    default: break;
  }

  *pu16ErrorCode = SNMPERRORNOSUCHNAME;
  return (FALSE);
}

/*************************************************************************************************/
/*  Name       : fn_StandardBlocksDefinitionRead                                                 */
/*                                                                                               */
/*  Description: Returns the specified block defintions in the format:                           */
/*    <oid octet> <type> <length>                                                                */
/*************************************************************************************************/
BOOLEAN fn_StandardBlocksDefinitionRead(TYPE_COMMS_MSG *psMsg, INT8U **ppu8Resp, INT16U *pu16SizResp, BOOLEAN bValidate, INT16U *pu16ErrorCode)
{

  INT8U u8TableIndex = 0; // Index to the table to acquire

  if (psMsg->boIsWriteTheValue) {
    *pu16ErrorCode = SNMPERRORREADONLY;
    return FALSE;
  }
  u8TableIndex = (INT8U)(psMsg->usObjectIndex[0]) - 1;

  if (!bMsgAppendTableDef(u8TableIndex, 0, ppu8Resp, pu16SizResp, pu16ErrorCode)) {
    return FALSE;
  }
  if (bValidate) {
    return FALSE;
  }
  return TRUE;
}

/*************************************************************************************************/
/*  Name       : fn_OmniBlocksDefinitionRead                                                     */
/*                                                                                               */
/*  Description: Returns the specified block defintions in the format:                           */
/*    <oid octet> <type> <length>                                                                */
/*************************************************************************************************/
BOOLEAN fn_OmniBlocksDefinitionRead(TYPE_COMMS_MSG *psMsg, INT8U **ppu8Resp, INT16U *pu16SizResp, BOOLEAN bValidate, INT16U *pu16ErrorCode)
{

  INT8U u8TableIndex = 0; // Index to the table to acquire

  if (psMsg->boIsWriteTheValue) {
    *pu16ErrorCode = SNMPERRORREADONLY;
    return FALSE;
  }
  u8TableIndex = (INT8U)(psMsg->usObjectIndex[0]) - 1;
  if (!bMsgAppendTableDef(u8TableIndex, 1, ppu8Resp, pu16SizResp, pu16ErrorCode)) {
    return FALSE;
  }
  if (bValidate) {
    return FALSE;
  }
  return TRUE;
}

/*************************************************************************************************/
/*  Name       : fn_mcRedLightProtection                                                         */
/*                                                                                               */
/*  Description: Handles the Red Light Protection objects.                                       */
/*    Note that these are 3 groups of objects, from patterns, phases and detectors.              */
/*************************************************************************************************/
BOOLEAN fn_mcRedLightProtection(TYPE_COMMS_MSG *ptMsg, INT8U **ppu8Resp, INT16U *pu16SizeResp, BOOLEAN bValidate, INT16U *pu16ErrorCode)
{
  const TYPE_OIDTABLE *ptOidRow = OID + ptMsg->usObjectRow;
  TYPE_ACCESS_FUNCTION_DATA tAccessFnData = {bValidate, ppu8Resp, pu16SizeResp, pu16ErrorCode, ptMsg, ptOidRow};
  BOOLEAN bErrorFlag = FALSE;
  INT16U u16Index1 = 0;
  INT16U u16Index2 = 0;

  switch (ptOidRow->oidPart[5]) {
    case 3: // The constants for each pattern
      switch (ptOidRow->oidPart[6]) {
        case 10:
          return bProcessU8Object(&tAccessFnData, &(ptMsg->ptNtcipParameters->u8McAtcRedLightProtectionActivationsPerCycle));
        case 11:
          return bProcessU8Object(&tAccessFnData, &(ptMsg->ptNtcipParameters->u8McAtcRedLightProtectionCycleHeadway));
        default:
          bErrorFlag = TRUE;
          break;
      }
      break;
    case 11: // The settings per phase
      u16Index1 = ptMsg->usObjectIndex[0] - 1;
      u16Index2 = ptMsg->usObjectIndex[1] - 1;
      switch (ptOidRow->oidPart[8]) {
        case 36:
          return bProcessU8Object(&tAccessFnData, &(ptMsg->ptNtcipParameters->atPhaseData[u16Index1][u16Index2].u8McAtcRedLightProtectionTime));
        case 37:
          return bProcessU8Object(&tAccessFnData, &(ptMsg->ptNtcipParameters->atPhaseData[u16Index1][u16Index2].u8McAtcRedLightProtectionMaxApplications));
        default:
          bErrorFlag = TRUE;
          break;
      }
      break;
    case 13: // The settings per detector
      if (ptOidRow->oidPart[8] == 16) {
        u16Index1 = ptMsg->usObjectIndex[0] - 1;
        u16Index2 = ptMsg->usObjectIndex[1] - 1;
        return bProcessU8Object(&tAccessFnData, &(ptMsg->ptNtcipParameters->atDetectorData[u16Index1][u16Index2].u8McAtcRedLightProtectionEnable));
      } else {
        bErrorFlag = TRUE;
      }
      break;
    default: // This would be a programming error
      bErrorFlag = TRUE;
      break;
  }
  if (bErrorFlag == TRUE) {
    vMcSysLog(LOG_ERR, "Error-Invalid Red Light Protect OID=%d", OID[ptMsg->usObjectRow].oidPart[5]);
    exit(-1);
  }
  return TRUE;
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

  for (u8Index = 0; u8Index < MAX_OID_INDICES; u8Index++) {
    if (OID[u16OidRow].oidIndexMax[u8Index] == 0) {
      break;
    }
  }
  return u8Index;
}

BOOLEAN fn_unitStartupFlashMode(TYPE_COMMS_MSG *ptrMsg, //!< [inout] message structure holding received message
                                INT8U **ptrResp,        //!< [inout] response buffer
                                INT16U *sizResp,        //!< [inout] response buffer size
                                BOOLEAN validate,       //!< only perform dry-run write if set
                                INT16U *errorCode)      //!< [out] return error code
{
  INT8U u8NewVal = 0;

  *errorCode = SNMPERRORNOERROR;

  if (ptrMsg->boIsWriteTheValue) {
    if (bDecodeUInt1(&ptrMsg->ucReadPointer, &u8NewVal, errorCode)) {
      if ((u8NewVal < OID[ptrMsg->usObjectRow].oidMin) || (u8NewVal > OID[ptrMsg->usObjectRow].oidMax)) {
        *errorCode = SNMPERRORBADVALUE;
        return FALSE;
      }
      if (validate) {
        return TRUE;
      }

      ptrMsg->ptNtcipParameters->unitStartupFlashMode = u8NewVal;
      if (eNtcipTableAccess == BLOCK_TABLE_DECODE) { // Skip response in decode mode
        return TRUE;
      }

      return bAppendUInt(ptrMsg->ptNtcipParameters->unitStartupFlashMode, ptrResp, sizResp, errorCode);
    }
  }
  return bAppendUInt(ptrMsg->ptNtcipParameters->unitStartupFlashMode, ptrResp, sizResp, errorCode);
}

/*************************************************************************************************/
/* Name : bStubFunction */
/* */
/* Description: Placeholder access function */
/* Returns the minimum value for the OID but does not set anything */
/*************************************************************************************************/
static BOOLEAN bStubFunction(TYPE_COMMS_MSG *ptCommsMsg, INT8U **ppu8Resp, INT16U *pu16SizeResp, BOOLEAN __attribute__((unused)) bValidate, INT16U *pu16ErrorCode)
{
  *pu16ErrorCode = SNMPERRORNOERROR;
  const TYPE_OIDTABLE *ptOidRow = OID + ptCommsMsg->usObjectRow;
  INT8U u8Value = 0;
  if (ptCommsMsg->boIsWriteTheValue) {
    bDecodeUInt1(&ptCommsMsg->ucReadPointer, &u8Value, pu16ErrorCode);
  }
  return bAppendUInt(ptOidRow->oidMin, ppu8Resp, pu16SizeResp, pu16ErrorCode);
}
// End Module OIDtable.c
