/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <libgen.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "securec.h"
#include "cJSON.h"
#include "endian_internal.h"
#include "create_pcid.h"

#define SINGLE_FEAT_LENGTH  (32 * 8)
#define PER_SYSCAP_LEN_MAX 128
#define PRIVATE_SYSCAP_SIZE 1000
#define BITS_OF_ONE_BYTE 8
#define BYTES_OF_OS_SYSCAP 120

#define PRINT_ERR(...) \
    do { \
        printf("ERROR: in file %s at line %d -> ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
    } while (0)

/* ensure sort by num */
static SyscapWithNum arraySyscap[] = {
    {"SystemCapability.Account.AppAccount", ACCOUNT_APPACCOUNT},
    {"SystemCapability.Account.OsAccount", ACCOUNT_OSACCOUNT},
    {"SystemCapability.Ace.AceEngineLite", ACE_ACEENGINELITE},
    {"SystemCapability.Ai.AiEngine", AI_AIENGINE},
    {"SystemCapability.Applications.ContactsData", APPLICATIONS_CONTACTSDATA},
    {"SystemCapability.Barrierfree.Accessibility.Core", BARRIERFREE_ACCESSIBILITY_CORE},
    {"SystemCapability.BundleManager.BundleFramework", BUNDLEMANAGER_BUNDLEFRAMEWORK},
    {"SystemCapability.BundleManager.BundleTool", BUNDLEMANAGER_BUNDLETOOL},
    {"SystemCapability.BundleManager.DistributedBundleFramework", BUNDLEMANAGER_DISTRIBUTEDBUNDLEFRAMEWORK},
    {"SystemCapability.BundleManager.Zlib", BUNDLEMANAGER_ZLIB},
    {"SystemCapability.Communication.Bluetooth.Core", COMMUNICATION_BLUETOOTH_CORE},
    {"SystemCapability.Communication.NetManager.Core", COMMUNICATION_NETMANAGER_CORE},
    {"SystemCapability.Communication.NetManager.Extension", COMMUNICATION_NETMANAGER_EXTENSION},
    {"SystemCapability.Communication.NetStack", COMMUNICATION_NETSTACK},
    {"SystemCapability.Communication.SoftBus.Core", COMMUNICATION_SOFTBUS_CORE},
    {"SystemCapability.Communication.WiFi.AP", COMMUNICATION_WIFI_AP},
    {"SystemCapability.Communication.WiFi.Core", COMMUNICATION_WIFI_CORE},
    {"SystemCapability.Communication.WiFi.HotspotExt", COMMUNICATION_WIFI_HOTSPOTEXT},
    {"SystemCapability.Communication.WiFi.P2P", COMMUNICATION_WIFI_P2P},
    {"SystemCapability.Communication.WiFi.STA", COMMUNICATION_WIFI_STA},
    {"SystemCapability.Customization.ConfigPolicy", CUSTOMIZATION_CONFIGPOLICY},
    {"SystemCapability.Customization.EnterpriseDeviceManager", CUSTOMIZATION_ENTERPRISEDEVICEMANAGER},
    {"SystemCapability.DistributedDataManager.DataObject.DistributedObject", DISTRIBUTEDDATAMANAGER_DATAOBJECT_DISTRIBUTEDOBJECT},
    {"SystemCapability.DistributedDataManager.DataShare.Consumer", DISTRIBUTEDDATAMANAGER_DATASHARE_CONSUMER},
    {"SystemCapability.DistributedDataManager.DataShare.Core", DISTRIBUTEDDATAMANAGER_DATASHARE_CORE},
    {"SystemCapability.DistributedDataManager.DataShare.Provider", DISTRIBUTEDDATAMANAGER_DATASHARE_PROVIDER},
    {"SystemCapability.DistributedDataManager.KVStore.Core", DISTRIBUTEDDATAMANAGER_KVSTORE_CORE},
    {"SystemCapability.DistributedDataManager.KVStore.DistributedKVStore", DISTRIBUTEDDATAMANAGER_KVSTORE_DISTRIBUTEDKVSTORE},
    {"SystemCapability.DistributedDataManager.KVStore.Lite", DISTRIBUTEDDATAMANAGER_KVSTORE_LITE},
    {"SystemCapability.DistributedDataManager.Preferences.Core", DISTRIBUTEDDATAMANAGER_PREFERENCES_CORE},
    {"SystemCapability.DistributedDataManager.RelationalStore.Core", DISTRIBUTEDDATAMANAGER_RELATIONALSTORE_CORE},
    {"SystemCapability.DistributedHardware.DeviceManager", DISTRIBUTEDHARDWARE_DEVICEMANAGER},
    {"SystemCapability.distributedhardware.distributed_camera", DISTRIBUTEDHARDWARE_DISTRIBUTED_CAMERA},
    {"SystemCapability.distributedhardware.distributed_hardware_fwk", DISTRIBUTEDHARDWARE_DISTRIBUTED_HARDWARE_FWK},
    {"SystemCapability.distributedhardware.distributed_screen", DISTRIBUTEDHARDWARE_DISTRIBUTED_SCREEN},
    {"SystemCapability.FileManagement.FileManagerService", FILEMANAGEMENT_FILEMANAGERSERVICE},
    {"SystemCapability.FileManagement.RemoteFileShare", FILEMANAGEMENT_REMOTEFILESHARE},
    {"SystemCapability.Global.ResourceManager", GLOBAL_RESOURCEMANAGER},
    {"SystemCapability.Graphic.Graphic2D.NativeDrawing", GRAPHIC_GRAPHIC2D_NATIVEDRAWING},
    {"SystemCapability.Graphic.Graphic2D.NativeWindow", GRAPHIC_GRAPHIC2D_NATIVEDRAWING},
    {"SystemCapability.Graphic.Graphic2D.WebGL", GRAPHIC_GRAPHIC2D_WEBGL},
    {"SystemCapability.Graphic.Graphic2D.WebGL2", GRAPHIC_GRAPHIC2D_WEBGL2},
    {"SystemCapability.Graphic.Surface", GRAPHIC_SURFACE},
    {"SystemCapability.Graphic.UI", GRAPHIC_UI},
    {"SystemCapability.Graphic.Utils", GRAPHIC_UTILS},
    {"SystemCapability.Graphic.Wms", GRAPHIC_WMS},
    {"SystemCapability.HiviewDFX.HiAppEvent", HIVIEWDFX_HIAPPEVENT},
    {"SystemCapability.HiviewDFX.HiDumper", HIVIEWDFX_HIDUMPER},
    {"SystemCapability.HiviewDFX.HiLog", HIVIEWDFX_HILOG},
    {"SystemCapability.HiviewDFX.HiLogLite", HIVIEWDFX_HILOGLITE},
    {"SystemCapability.HiviewDFX.HiProfiler.HiDebug", HIVIEWDFX_HIPROFILER_HIDEBUG},
    {"SystemCapability.HiviewDFX.HiSysEvent", HIVIEWDFX_HISYSEVENT},
    {"SystemCapability.HiviewDFX.HiTrace", HIVIEWDFX_HITRACE},
    {"SystemCapability.HiviewDFX.Hiview", HIVIEWDFX_HIVIEW},
    {"SystemCapability.HiviewDFX.Hiview.FaultLogger", HIVIEWDFX_HIVIEW_FAULTLOGGER},
    {"SystemCapability.I18N", I18N},
    {"SystemCapability.Global.I18n", GLOBAL_I18N},
    {"SystemCapability.Kernel.Linux", KERNEL_LINUX},
    {"SystemCapability.Kernel.liteos-a", KERNEL_LITEOS_A},
    {"SystemCapability.Location.Location", LOCATION_LOCATION},
    {"SystemCapability.MiscServices.download", MISCSERVICES_DOWNLOAD},
    {"SystemCapability.Miscservices.InputMethod", MISCSERVICES_INPUTMETHOD},
    {"SystemCapability.Miscservices.Pasteboard", MISCSERVICES_PASTEBOARD},
    {"SystemCapability.MiscServices.ScreenLock", MISCSERVICES_SCREENLOCK},
    {"SystemCapability.MiscServices.Time", MISCSERVICES_TIME},
    {"SystemCapability.MiscServices.Upload", MISCSERVICES_UPLOAD},
    {"SystemCapability.MiscServices.Wallpaper", MISCSERVICES_WALLPAPER},
    {"SystemCapability.Msdp.DeviceStatus", MSDP_DEVICESTATUS},
    {"SystemCapability.Multimedia.MediaLibrary", MULTIMEDIA_MEDIALIBRARY},
    {"SystemCapability.Multimedia.Media.AudioPlayer", MULTIMEDIA_MEDIA_AUDIOPLAYER},
    {"SystemCapability.Multimedia.Media.AudioRecorder", MULTIMEDIA_MEDIA_AUDIORECORDER},
    {"SystemCapability.Multimedia.Media.Codec", MULTIMEDIA_MEDIA_CODEC},
    {"SystemCapability.Multimedia.Media.Core", MULTIMEDIA_MEDIA_CORE},
    {"SystemCapability.Multimedia.Media.Muxer", MULTIMEDIA_MEDIA_MUXER},
    {"SystemCapability.Multimedia.Image", MULTIMEDIA_IMAGE},
    {"SystemCapability.Multimedia.Image.Core", MULTIMEDIA_IMAGE_CORE},
    {"SystemCapability.Multimedia.Image.ImageSource", MULTIMEDIA_IMAGE_IMAGESOURCE},
    {"SystemCapability.Multimedia.Image.ImagePacker", MULTIMEDIA_IMAGE_IMAGEPACKER},
    {"SystemCapability.Multimedia.Image.ImageReceiver", MULTIMEDIA_IMAGE_IMAGERECEIVER},
    {"SystemCapability.Multimedia.Media.Spliter", MULTIMEDIA_MEDIA_SPLITER},
    {"SystemCapability.Multimedia.Media.VideoPlayer", MULTIMEDIA_MEDIA_VIDEOPLAYER},
    {"SystemCapability.Multimedia.Media.VideoRecorder", MULTIMEDIA_MEDIA_VIDEORECORDER},
    {"SystemCapability.multimodalinput.input", MULTIMODALINPUT_INPUT},
    {"SystemCapability.Notification.CommonEvent", NOTIFICATION_COMMONEVENT},
    {"SystemCapability.Notification.Emitter", NOTIFICATION_EMITTER},
    {"SystemCapability.Notification.Notification", NOTIFICATION_NOTIFICATION},
    {"SystemCapability.Notification.ReminderAgent", NOTIFICATION_REMINDERAGENT},
    {"SystemCapability.PowerManager.BatteryManager.Core", POWERMANAGER_BATTERYMANAGER_CORE},
    {"SystemCapability.PowerManager.BatteryManager.Extension", POWERMANAGER_BATTERYMANAGER_EXTENSION},
    {"SystemCapability.PowerManager.BatteryManager.Lite", POWERMANAGER_BATTERYMANAGER_LITE},
    {"SystemCapability.PowerManager.BatteryStatistics", POWERMANAGER_BATTERYSTATISTICS},
    {"SystemCapability.PowerManager.DisplayPowerManager", POWERMANAGER_DISPLAYPOWERMANAGER},
    {"SystemCapability.PowerManager.PowerManager.Core", POWERMANAGER_POWERMANAGER_CORE},
    {"SystemCapability.PowerManager.PowerManager.Extension", POWERMANAGER_POWERMANAGER_EXTENSION},
    {"SystemCapability.PowerManager.PowerManager.Lite", POWERMANAGER_POWERMANAGER_LITE},
    {"SystemCapability.PowerManager.ThermalManager", POWERMANAGER_THERMALMANAGER},
    {"SystemCapability.ResourceSchedule.BackgroundTaskManager.ContinuousTask", RESOURCESCHEDULE_BACKGROUNDTASKMANAGER_CONTINUOUSTASK},
    {"SystemCapability.ResourceSchedule.BackgroundTaskManager.TransientTask", RESOURCESCHEDULE_BACKGROUNDTASKMANAGER_TRANSIENTTASK},
    {"SystemCapability.ResourceSchedule.UsageStatistics.App", RESOURCESCHEDULE_USAGESTATISTICS_APP},
    {"SystemCapability.ResourceSchedule.UsageStatistics.AppGroup", RESOURCESCHEDULE_USAGESTATISTICS_APPGROUP},
    {"SystemCapability.ResourceSchedule.WorkScheduler", RESOURCESCHEDULE_WORKSCHEDULER},
    {"SystemCapability.Security.AccessToken", SECURITY_ACCESSTOKEN},
    {"SystemCapability.Security.AppVerify", SECURITY_APPVERIFY},
    {"SystemCapability.Security.DataTransitManager", SECURITY_DATATRANSITMANAGER},
    {"SystemCapability.Security.DeviceAuth", SECURITY_DEVICEAUTH},
    {"SystemCapability.Security.DeviceSecurityLevel", SECURITY_DEVICESECURITYLEVEL},
    {"SystemCapability.Security.Huks", SECURITY_HUKS},
    {"SystemCapability.Sensors.MiscDevice", SENSORS_MISCDEVICE},
    {"SystemCapability.Sensors.Sensor", SENSORS_SENSOR},
    {"SystemCapability.Sensors.Sensor_lite", SENSORS_SENSOR_LITE},
    {"SystemCapability.Telephony.CallManager", TELEPHONY_CALLMANAGER},
    {"SystemCapability.Telephony.CellularCall", TELEPHONY_CELLULARCALL},
    {"SystemCapability.Telephony.CellularData", TELEPHONY_CELLULARDATA},
    {"SystemCapability.Telephony.CoreService", TELEPHONY_CORESERVICE},
    {"SystemCapability.Telephony.DataStorage", TELEPHONY_DATASTORAGE},
    {"SystemCapability.Telephony.DCall", TELEPHONY_DCALL},
    {"SystemCapability.Telephony.SmsMms", TELEPHONY_SMSMMS},
    {"SystemCapability.Telephony.StateRegistry", TELEPHONY_STATEREGISTRY},
    {"SystemCapability.Test.UiTest", TEST_UITEST},
    {"SystemCapability.Test.WuKong", TEST_WUKONG},
    {"SystemCapability.Updater.Raw", UPDATER_RAW},
    {"SystemCapability.Update.UpdateService", UPDATE_UPDATESERVICE},
    {"SystemCapability.USB.USBManager", USB_USBMANAGER},
    {"SystemCapability.UserIAM.AuthExecutorManager", USERIAM_AUTHEXECUTORMANAGER},
    {"SystemCapability.UserIAM.UserAuth.Core", USERIAM_USERAUTH_CORE},
    {"SystemCapability.UserIAM.UserAuth.FaceAuth", USERIAM_USERAUTH_FACEAUTH},
    {"SystemCapability.UserIAM.UserAuth.PinAuth", USERIAM_USERAUTH_PINAUTH},
    {"SystemCapability.UserIAM.UserIdm", USERIAM_USERIDM}
};

static void FreeContextBuffer(char *contextBuffer)
{
    (void)free(contextBuffer);
}

static uint32_t GetFileContext(char *inputFile, char **contextBufPtr, uint32_t *contextBufLen)
{
    uint32_t ret;
    FILE *fp = NULL;
    struct stat statBuf;
    char *contextBuffer = NULL;

    ret = stat(inputFile, &statBuf);
    if (ret != 0) {
        PRINT_ERR("get file(%s) st_mode failed, errno = %d\n", inputFile, errno);
        return -1;
    }
    if (!(statBuf.st_mode & S_IRUSR)) {
        PRINT_ERR("don't have permission to read the file(%s)\n", inputFile);
        return -1;
    }
    contextBuffer = (char *)malloc(statBuf.st_size + 1);
    if (contextBuffer == NULL) {
        PRINT_ERR("malloc buffer failed, size = %d, errno = %d\n", (int32_t)statBuf.st_size + 1, errno);
        return -1;
    }
    fp = fopen(inputFile, "rb");
    if (fp == NULL) {
        PRINT_ERR("open file(%s) failed, errno = %d\n", inputFile, errno);
        FreeContextBuffer(contextBuffer);
        return -1;
    }
    ret = fread(contextBuffer, statBuf.st_size, 1, fp);
    if (ret != 1) {
        PRINT_ERR("read file(%s) failed, errno = %d\n", inputFile, errno);
        FreeContextBuffer(contextBuffer);
        (void)fclose(fp);
        return -1;
    }
    contextBuffer[statBuf.st_size] = '\0';
    (void)fclose(fp);

    *contextBufPtr = contextBuffer;
    *contextBufLen = statBuf.st_size + 1;
    return 0;
}

static int32_t ConvertedContextSaveAsFile(char *outDirPath, const char *filename, \
                                          char *convertedBuffer, uint32_t contextBufLen)
{
    int32_t ret;
    FILE *fp = NULL;
    char fileFullPath[PATH_MAX] = {0};
    int32_t pathLen = strlen(outDirPath);

    ret = strncpy_s(fileFullPath, PATH_MAX, outDirPath, pathLen + 1);
    if (ret != 0) {
        PRINT_ERR("strncpy_s failed, source string:%s, len = %d, errno = %d\n", outDirPath, pathLen + 1, errno);
        return -1;
    }

    if (fileFullPath[pathLen - 1] != '/' && fileFullPath[pathLen - 1] != '\\') {
        fileFullPath[pathLen] = '/';
    }

    ret = strncat_s(fileFullPath, PATH_MAX, filename, strlen(filename) + 1);
    if (ret != 0) {
        PRINT_ERR("strncat_s failed, (%s, %d, %s, %d), errno = %d\n",
                  fileFullPath, PATH_MAX, filename, (int32_t)strlen(filename) + 1, errno);
        return -1;
    }

    fp = fopen(fileFullPath, "wb");
    if (fp == NULL) {
        PRINT_ERR("can`t create file(%s), errno = %d\n", fileFullPath, errno);
        return -1;
    }

    ret = fwrite(convertedBuffer, contextBufLen, 1, fp);
    if (ret != 1) {
        PRINT_ERR("can`t write file(%s),errno = %d\n", fileFullPath, errno);
        (void)fclose(fp);
        return -1;
    }

    (void)fclose(fp);

    return 0;
}

static cJSON *CreateWholeSyscapJsonObj(void)
{
    size_t numOfSyscapAll = sizeof(arraySyscap) / sizeof(SyscapWithNum);
    cJSON *root =  cJSON_CreateObject();
    for (size_t i = 0; i < numOfSyscapAll; i++) {
        cJSON_AddItemToObject(root, arraySyscap[i].syscapStr, cJSON_CreateNumber(arraySyscap[i].num));
    }
    return root;
}

int32_t CreatePCID(char *inputFile, char *outDirPath)
{
    uint8_t sectorOfBits, posOfBits;
    int32_t ret, i;
    uint32_t contextBufLen, osCapSize, privateCapSize;
    errno_t nRet = 0;
    char *contextBuffer = NULL;
    char *systemType = NULL;
    cJSON *jsonRootObj = NULL;
    cJSON *jsonSyscapObj = NULL;
    cJSON *jsonOsSyscapObj = NULL;
    cJSON *jsonPriSyscapObj = NULL;
    cJSON *jsonArrayItem = NULL;
    cJSON *osCapIndex = NULL;
    cJSON *allOsSyscapObj = CreateWholeSyscapJsonObj();

    ret = GetFileContext(inputFile, &contextBuffer, &contextBufLen);
    if (ret != 0) {
        PRINT_ERR("GetFileContext failed, input file : %s\n", inputFile);
        return -1;
    }

    jsonRootObj = cJSON_ParseWithLength(contextBuffer, contextBufLen);
    if (jsonRootObj == NULL) {
        PRINT_ERR("cJSON_Parse failed, context buffer is:\n%s\n", contextBuffer);
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    jsonSyscapObj = cJSON_GetObjectItem(jsonRootObj, "syscap");
    if (jsonSyscapObj == NULL || !cJSON_IsObject(jsonSyscapObj)) {
        PRINT_ERR("get \"syscap\" object failed, jsonSyscapObj = %p\n", jsonSyscapObj);
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    jsonOsSyscapObj = cJSON_GetObjectItem(jsonSyscapObj, "os");
    if (jsonOsSyscapObj == NULL || !cJSON_IsArray(jsonOsSyscapObj)) {
        PRINT_ERR("get \"os\" array failed, jsonOsSyscapObj = %p\n", jsonOsSyscapObj);
        ret = -1;
        goto FREE_CONVERT_OUT;
    }
    osCapSize = cJSON_GetArraySize(jsonOsSyscapObj);
    if (osCapSize < 0) {
        PRINT_ERR("get \"os\" array size failed\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    jsonPriSyscapObj = cJSON_GetObjectItem(jsonSyscapObj, "private");
    if (jsonPriSyscapObj != NULL && cJSON_IsArray(jsonPriSyscapObj)) {
        privateCapSize = cJSON_GetArraySize(jsonPriSyscapObj);
    } else if (jsonPriSyscapObj == NULL) {
        privateCapSize = 0;
    } else {
        PRINT_ERR("get \"private\" array failed, jsonPriSyscapObj = %p\n", jsonPriSyscapObj);
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    uint16_t allPriSyscapStrLen = 0;
    for (i = 0; i < privateCapSize; i++) {
        jsonArrayItem = cJSON_GetArrayItem(jsonPriSyscapObj, i);
        allPriSyscapStrLen += strlen(strchr(jsonArrayItem->valuestring, '.') + 1);
        allPriSyscapStrLen++;  // for separator ','
    }
    if ((allPriSyscapStrLen + 1) > PRIVATE_SYSCAP_SIZE) {
        PRINT_ERR("context of \"pri\" array is too many\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    uint16_t PCIDLength = sizeof(PCIDMain) + allPriSyscapStrLen + 1;
    PCIDMain *PCIDBuffer = (PCIDMain *)malloc(PCIDLength);
    if (PCIDBuffer == NULL) {
        PRINT_ERR("malloc for pcid buffer failed\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }
    (void)memset_s(PCIDBuffer, PCIDLength, 0, PCIDLength);
    
    // process os syscap
    for (i = 0; i < osCapSize; i++) {
        jsonArrayItem = cJSON_GetArrayItem(jsonOsSyscapObj, i);
        osCapIndex = cJSON_GetObjectItem(allOsSyscapObj, jsonArrayItem->valuestring);
        if (osCapIndex == NULL) {
            PRINT_ERR("can't find the syscap: %s, please checkout.\n", jsonArrayItem->valuestring);
            ret = -1;
            goto FREE_CONVERT_OUT;
        }
        sectorOfBits = (osCapIndex->valueint) / BITS_OF_ONE_BYTE;
        posOfBits = (osCapIndex->valueint) % BITS_OF_ONE_BYTE;
        if (sectorOfBits >= BYTES_OF_OS_SYSCAP) {
            PRINT_ERR("num of \"os syscap\" is out of 960\n");
            ret = -1;
            goto FREE_PCID_BUFFER_OUT;
        }
        PCIDBuffer->osSyscap[sectorOfBits] |= 1 << (posOfBits);
    }

    // process private syscap
    char *priSyscapHead = (char *)(PCIDBuffer + 1);
    char *priSyscapStr = NULL;
    for (i = 0; i < privateCapSize; i++) {
        jsonArrayItem = cJSON_GetArrayItem(jsonPriSyscapObj, i);
        priSyscapStr = strchr(jsonArrayItem->valuestring, '.') + 1;
        nRet = strcat_s(priSyscapHead, PRIVATE_SYSCAP_SIZE - 1, priSyscapStr);
        nRet += strcat_s(priSyscapHead, PRIVATE_SYSCAP_SIZE - 1, ",");
        if (nRet != EOK) {
            PRINT_ERR("strcat_s \"pri\" string is failed\n");
            ret = -1;
            goto FREE_PCID_BUFFER_OUT;
        }
    }

    jsonSyscapObj = cJSON_GetObjectItem(jsonRootObj, "api_version");
    if (jsonSyscapObj == NULL || !cJSON_IsNumber(jsonSyscapObj)) {
        PRINT_ERR("get \"api_version\" failed, jsonSyscapObj = %p\n", jsonSyscapObj);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }
    PCIDBuffer->apiVersion = HtonsInter((uint16_t)jsonSyscapObj->valueint);
    PCIDBuffer->apiVersionType = 0;

    jsonSyscapObj = cJSON_GetObjectItem(jsonRootObj, "system_type");
    if (jsonSyscapObj == NULL || !cJSON_IsString(jsonSyscapObj)) {
        PRINT_ERR("get \"system_type\" failed, jsonSyscapObj = %p\n", jsonSyscapObj);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }
    systemType = jsonSyscapObj->valuestring;
    PCIDBuffer->systemType = !strcmp(systemType, "mini") ? 0b001 :
                          (!strcmp(systemType, "small") ? 0b010 :
                          (!strcmp(systemType, "standard") ? 0b100 : 0));
    if (PCIDBuffer->systemType == 0) {
        PRINT_ERR("\"system_type\" is invaild, systemType = \"%s\"\n", systemType);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }

    jsonSyscapObj = cJSON_GetObjectItem(jsonRootObj, "manufacturer_id");
    if (jsonSyscapObj == NULL || !cJSON_IsNumber(jsonSyscapObj)) {
        PRINT_ERR("get \"manufacturer_id\" failed, jsonSyscapObj = %p\n", jsonSyscapObj);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }
    PCIDBuffer->manufacturerID = HtonlInter((uint32_t)jsonSyscapObj->valueint);

    const char pcidFileName[] = "PCID.sc";
    ret = ConvertedContextSaveAsFile(outDirPath, pcidFileName, (char *)PCIDBuffer, PCIDLength);
    if (ret != 0) {
        PRINT_ERR("ConvertedContextSaveAsFile failed, outDirPath:%s, filename:%s\n", outDirPath, pcidFileName);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }

FREE_PCID_BUFFER_OUT:
    free(PCIDBuffer);
FREE_CONVERT_OUT:
    free(allOsSyscapObj);
    FreeContextBuffer(contextBuffer);
    return ret;
}

int32_t DecodePCID(char *inputFile, char *outDirPath)
{
    int32_t ret, i, j;
    errno_t nRet = 0;
    char *contextBuffer = NULL;
    uint8_t osSyscap[BYTES_OF_OS_SYSCAP] = {0};
    uint16_t indexOfSyscap[960] = {0};
    uint32_t contextBufLen, countOfSyscap = 0;

    ret = GetFileContext(inputFile, &contextBuffer, &contextBufLen);
    if (ret != 0) {
        PRINT_ERR("GetFileContext failed, input file : %s\n", inputFile);
        return -1;
    }

    PCIDMain *pcidMain = (PCIDMain *)contextBuffer;
    
    /* api version */
    if (pcidMain->apiVersionType != 0) {
        PRINT_ERR("prase file failed, apiVersionType is invaild, input file : %s\n", inputFile);
        ret = -1;
        goto FREE_CONTEXT_OUT;
    }

    /* system type */
    char *systemType = pcidMain->systemType == 0b001 ? "mini" :
                       (pcidMain->systemType == 0b010 ? "small" :
                       (pcidMain->systemType == 0b100 ? "standard" : NULL));
    if (systemType == NULL) {
        PRINT_ERR("prase file failed, systemType is invaild, %d\n", pcidMain->systemType);
        ret = -1;
        goto FREE_CONTEXT_OUT;
    }
    
    cJSON *capVectorPtr = cJSON_CreateArray();
    if (capVectorPtr == NULL) {
        PRINT_ERR("cJSON_CreateArray failed\n");
        ret = -1;
        goto FREE_CONTEXT_OUT;
    }

    nRet = memcpy_s(osSyscap, BYTES_OF_OS_SYSCAP, (uint8_t *)pcidMain + 8, BYTES_OF_OS_SYSCAP); // 8, bytes of pcid header
    if (EOK != nRet) {
        PRINT_ERR("memcpy_s failed.");
        ret = -1;
        goto FREE_VECTOR_OUT;
    }
    for (i = 0; i < BYTES_OF_OS_SYSCAP; i++) {
        for (j = 0; j < BITS_OF_ONE_BYTE; j++) {
            if (osSyscap[i] & (0x01 << j)) {
                indexOfSyscap[countOfSyscap++] = i * BITS_OF_ONE_BYTE + j;
            }
        }
    }
    for (i = 0; i < countOfSyscap; i++) {
        for (j = 0; j < sizeof(arraySyscap) / sizeof(SyscapWithNum); j++) {
            if (arraySyscap[j].num == indexOfSyscap[i]) {
                if (!cJSON_AddItemToArray(capVectorPtr, cJSON_CreateString(arraySyscap[j].syscapStr))) {
                    printf("cJSON_AddItemToArray or cJSON_CreateString failed\n");
                    ret = -1;
                    goto FREE_VECTOR_OUT;
                }
            }
        }
    }

    cJSON *sysCapObjectPtr = cJSON_CreateObject();
    if (sysCapObjectPtr == NULL) {
        PRINT_ERR("cJSON_CreateObject failed\n");
        ret = -1;
        goto FREE_CONTEXT_OUT;
    }
    if (!cJSON_AddItemToObject(sysCapObjectPtr, "os", capVectorPtr)) {
        PRINT_ERR("cJSON_AddItemToObject failed\n");
        ret = -1;
        goto FREE_VECTOR_OUT;
    }
    // private syscap
    capVectorPtr = cJSON_CreateArray();
    if (capVectorPtr == NULL) {
        PRINT_ERR("cJSON_CreateArray failed\n");
        ret = -1;
        goto FREE_SYSCAP_OUT;
    }

    char *ptrPrivateSyscap = (char *)(pcidMain + 1);
    uint16_t privateSyscapLen = contextBufLen - sizeof(PCIDMain) - 1;
    char priSyscapStr[PER_SYSCAP_LEN_MAX] = {0};
    char *tempPriSyscapStr = priSyscapStr;
    char fullPriSyscapStr[PER_SYSCAP_LEN_MAX] = {0};
    if (privateSyscapLen < 0) {
        PRINT_ERR("parse private syscap failed.");
        ret = -1;
        goto FREE_VECTOR_OUT;
    } else if (privateSyscapLen == 0) {
        goto SKIP_GET_PRIVATE;
    }

    while (*ptrPrivateSyscap != '\0') {
        if (*ptrPrivateSyscap == ',') {
            *tempPriSyscapStr = '\0';
            ret = sprintf_s(fullPriSyscapStr, PER_SYSCAP_LEN_MAX, "SystemCapability.%s", priSyscapStr);
            if (ret == -1) {
                printf("sprintf_s failed\n");
                goto FREE_VECTOR_OUT;
            }
            if (!cJSON_AddItemToArray(capVectorPtr, cJSON_CreateString(fullPriSyscapStr))) {
                printf("cJSON_AddItemToArray or cJSON_CreateString failed\n");
                ret = -1;
                goto FREE_VECTOR_OUT;
            }
            tempPriSyscapStr = priSyscapStr;
            ptrPrivateSyscap++;
            continue;
        }
        *tempPriSyscapStr++ = *ptrPrivateSyscap++;
    }
    if (!cJSON_AddItemToObject(sysCapObjectPtr, "private", capVectorPtr)) {
        PRINT_ERR("cJSON_AddItemToObject failed\n");
        ret = -1;
        goto FREE_VECTOR_OUT;
    }

SKIP_GET_PRIVATE:
    capVectorPtr = NULL;
    // create json root
    cJSON *jsonRootObj = cJSON_CreateObject();
    if (jsonRootObj == NULL) {
        PRINT_ERR("cJSON_CreateObject failed\n");
        ret = -1;
        goto FREE_SYSCAP_OUT;
    }

    if (!cJSON_AddNumberToObject(jsonRootObj, "api_version", NtohsInter(pcidMain->apiVersion))) {
        PRINT_ERR("cJSON_AddNumberToObject failed\n");
        ret = -1;
        goto FREE_ROOT_OUT;
    }
    if (!cJSON_AddNumberToObject(jsonRootObj, "manufacturer_id", NtohlInter(pcidMain->manufacturerID))) {
        PRINT_ERR("cJSON_AddNumberToObject failed\n");
        ret = -1;
        goto FREE_ROOT_OUT;
    }
    if (!cJSON_AddStringToObject(jsonRootObj, "system_type", systemType)) {
        PRINT_ERR("cJSON_AddStringToObject failed\n");
        ret = -1;
        goto FREE_ROOT_OUT;
    }
    if (!cJSON_AddItemToObject(jsonRootObj, "syscap", sysCapObjectPtr)) {
        PRINT_ERR("cJSON_AddItemToObject failed\n");
        ret = -1;
        goto FREE_ROOT_OUT;
    }
    sysCapObjectPtr = NULL;

    char *convertedBuffer = cJSON_Print(jsonRootObj);

    const char outputFileName[] = "PCID.json";
    ret = ConvertedContextSaveAsFile(outDirPath, outputFileName, convertedBuffer, strlen(convertedBuffer));
    if (ret != 0) {
        PRINT_ERR("ConvertedContextSaveAsFile failed, outDirPath:%s, filename:%s\n", outDirPath, outputFileName);
        goto FREE_CONVERT_OUT;
    }

FREE_CONVERT_OUT:
    free(convertedBuffer);
FREE_ROOT_OUT:
    cJSON_Delete(jsonRootObj);
FREE_SYSCAP_OUT:
    cJSON_Delete(sysCapObjectPtr);
FREE_VECTOR_OUT:
    cJSON_Delete(capVectorPtr);
FREE_CONTEXT_OUT:
    FreeContextBuffer(contextBuffer);
    return ret;
}