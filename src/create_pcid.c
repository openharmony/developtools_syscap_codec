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
#define BITS_OF_BYTE 8

#define PRINT_ERR(...) \
    do { \
        printf("ERROR: in file %s at line %d -> ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
    } while (0)

const char osSyscapStrHead[] = "SystemCapability.";

SyscapWithNum arraySyscap[] = {
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
    {"SystemCapability.DistributedDataManager.KVStore.Lite", DISTRIBUTEDDATAMANAGER_KVSTORE_DISTRIBUTEDKVSTORE},
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
    {"SystemCapability.Graphic.Graphic2D.WebGL2", GRAPHIC_GRAPHIC2D_WEBGL},
    {"SystemCapability.Graphic.Surface", GRAPHIC_SURFACE},
    {"SystemCapability.Graphic.UI", GRAPHIC_UI},
    {"SystemCapability.Graphic.Utils", GRAPHIC_UI},
    {"SystemCapability.Graphic.Wms", GRAPHIC_UI},
    {"SystemCapability.HiviewDFX.HiAppEvent", HIVIEWDFX_HIAPPEVENT},
    {"SystemCapability.HiviewDFX.HiDumper", HIVIEWDFX_HIDUMPER},
    {"SystemCapability.HiviewDFX.HiLog", HIVIEWDFX_HIDUMPER},
    {"SystemCapability.HiviewDFX.HiLogLite", HIVIEWDFX_HILOGLITE},
    {"SystemCapability.HiviewDFX.HiProfiler.HiDebug", HIVIEWDFX_HILOGLITE},
    {"SystemCapability.HiviewDFX.HiSysEvent", HIVIEWDFX_HISYSEVENT},
    {"SystemCapability.HiviewDFX.HiTrace", HIVIEWDFX_HITRACE},
    {"SystemCapability.HiviewDFX.Hiview", HIVIEWDFX_HIVIEW},
    {"SystemCapability.HiviewDFX.Hiview.FaultLogger", HIVIEWDFX_HIVIEW_FAULTLOGGER},
    {"SystemCapability.I18N", I18N},
    {"SystemCapability.Global.I18n", GLOBAL_I18N},
    {"SystemCapability.Kernel.liteos-a", KERNEL_LITEOS_A},
    {"SystemCapability.Location.Location", LOCATION_LOCATION},
    {"SystemCapability.MiscServices.download", MISCSERVICES_DOWNLOAD},
    {"SystemCapability.Miscservices.InputMethod", MISCSERVICES_INPUTMETHOD},
    {"SystemCapability.Miscservices.Pasteboard", MISCSERVICES_PASTEBOARD},
    {"SystemCapability.MiscServices.ScreenLock", MISCSERVICES_SCREENLOCK},
    {"SystemCapability.MiscServices.Time", MISCSERVICES_TIME},
    {"SystemCapability.MiscServices.Upload", MISCSERVICES_TIME},
    {"SystemCapability.MiscServices.Wallpaper", MISCSERVICES_WALLPAPER},
    {"SystemCapability.Msdp.DeviceStatus", MSDP_DEVICESTATUS},
    {"SystemCapability.Multimedia.Media.AudioPlayer", MULTIMEDIA_MEDIA_AUDIOPLAYER},
    {"SystemCapability.Multimedia.Media.AudioRecorder", MULTIMEDIA_MEDIA_AUDIOPLAYER},
    {"SystemCapability.Multimedia.Media.Codec", MULTIMEDIA_MEDIA_CODEC},
    {"SystemCapability.Multimedia.Media.Core", MULTIMEDIA_MEDIA_CORE},
    {"SystemCapability.Multimedia.Media.Muxer", MULTIMEDIA_MEDIA_MUXER},
    {"SystemCapability.Multimedia.Media.Spliter", MULTIMEDIA_MEDIA_SPLITER},
    {"SystemCapability.Multimedia.Media.VideoPlayer", MULTIMEDIA_MEDIA_VIDEOPLAYER},
    {"SystemCapability.Multimedia.Media.VideoRecorder", MULTIMEDIA_MEDIA_VIDEOPLAYER},
    {"SystemCapability.Multimedia.MediaLibrary", MULTIMEDIA_MEDIALIBRARY},
    {"SystemCapability.Multimedia.Image", MULTIMEDIA_IMAGE},
    {"SystemCapability.Multimedia.Image.Core", MULTIMEDIA_IMAGE_CORE},
    {"SystemCapability.Multimedia.Image.ImageSource", MULTIMEDIA_IMAGE_IMAGESOURCE},
    {"SystemCapability.Multimedia.Image.ImagePacker", MULTIMEDIA_IMAGE_IMAGEPACKER},
    {"SystemCapability.Multimedia.Image.ImageReceiver", MULTIMEDIA_IMAGE_IMAGERECEIVER},
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
    {"SystemCapability.Telephony.CallManager", SENSORS_SENSOR_LITE},
    {"SystemCapability.Telephony.CellularCall", TELEPHONY_CELLULARCALL},
    {"SystemCapability.Telephony.CellularData", TELEPHONY_CELLULARDATA},
    {"SystemCapability.Telephony.CoreService", TELEPHONY_CORESERVICE},
    {"SystemCapability.Telephony.DataStorage", TELEPHONY_DATASTORAGE},
    {"SystemCapability.Telephony.DCall", TELEPHONY_DCALL},
    {"SystemCapability.Telephony.SmsMms", TELEPHONY_SMSMMS},
    {"SystemCapability.Telephony.StateRegistry", TELEPHONY_STATEREGISTRY},
    {"SystemCapability.Test.UiTest", TEST_UITEST},
    {"SystemCapability.Test.WuKong", TEST_WUKONG},
    {"SystemCapability.Update.UpdateService", UPDATE_UPDATESERVICE},
    {"SystemCapability.Updater.Raw", UPDATER_RAW},
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

static uint32_t GetFileContext(char *inputFile, char **contextBufPtr, uint32_t *bufferLen)
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
    *bufferLen = statBuf.st_size + 1;
    return 0;
}

static int32_t ConvertedContextSaveAsFile(char *outDirPath, char *filename, char *convertedBuffer, uint32_t bufferLen)
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

    ret = fwrite(convertedBuffer, bufferLen, 1, fp);
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
    int32_t ret, osCapSize, privateCapSize;
    uint32_t bufferLen;
    char *contextBuffer = NULL;
    char *systemType = NULL;
    char productName[NAME_MAX] = {0};
    cJSON *cjsonObjectRoot = NULL;
    cJSON *cjsonObjectPtr = NULL;
    cJSON *osCapPtr = NULL;
    cJSON *privateCapPtr = NULL;
    cJSON *arrayItemPtr = NULL;
    cJSON *allOsSyscapObj = CreateWholeSyscapJsonObj();

    ret = GetFileContext(inputFile, &contextBuffer, &bufferLen);
    if (ret != 0) {
        PRINT_ERR("GetFileContext failed, input file : %s\n", inputFile);
        return -1;
    }

    cjsonObjectRoot = cJSON_ParseWithLength(contextBuffer, bufferLen);
    if (cjsonObjectRoot == NULL) {
        PRINT_ERR("cJSON_Parse failed, context buffer is:\n%s\n", contextBuffer);
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    cjsonObjectPtr = cJSON_GetObjectItem(cjsonObjectRoot, "syscap");
    if (cjsonObjectPtr == NULL || !cJSON_IsObject(cjsonObjectPtr)) {
        PRINT_ERR("get \"syscap\" object failed, cjsonObjectPtr = %p\n", cjsonObjectPtr);
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    osCapPtr = cJSON_GetObjectItem(cjsonObjectPtr, "os");
    if (osCapPtr == NULL || !cJSON_IsArray(osCapPtr)) {
        PRINT_ERR("get \"os\" array failed, osCapPtr = %p\n", osCapPtr);
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    osCapSize = cJSON_GetArraySize(osCapPtr);
    if (osCapSize < 0) {
        PRINT_ERR("get \"os\" array size failed\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    privateCapPtr = cJSON_GetObjectItem(cjsonObjectPtr, "private");
    if (privateCapPtr != NULL && cJSON_IsArray(privateCapPtr)) {
        privateCapSize = cJSON_GetArraySize(privateCapPtr);
    } else if (privateCapPtr == NULL) {
        privateCapSize = 0;
    } else {
        PRINT_ERR("get \"private\" array failed, privateCapPtr = %p\n", privateCapPtr);
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    if (privateCapSize * PER_SYSCAP_LEN_MAX > PRIVATE_SYSCAP_SIZE) {
        PRINT_ERR("context of \"pri\" array is too many\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }
    uint32_t PCIDBufferLen = sizeof(PCIDMain) + privateCapSize * PER_SYSCAP_LEN_MAX;
    PCIDMain *PCIDBuffer = (PCIDMain *)malloc(PCIDBufferLen);
    if (PCIDBuffer == NULL) {
        PRINT_ERR("malloc for pcid buffer failed\n");
        ret = -1;
        goto FREE_CONVERT_OUT;
    }
    (void)memset_s(PCIDBuffer, PCIDBufferLen, 0, PCIDBufferLen);

    for (int32_t i = 0; i < osCapSize; i++) {
        arrayItemPtr = cJSON_GetArrayItem(osCapPtr, i);
        ret = strncmp(arrayItemPtr->valuestring, osSyscapStrHead, strlen(osSyscapStrHead));
        if (ret != 0) {
            PRINT_ERR("context of \"os\" array is invaild\n");
            ret = -1;
            goto FREE_PCID_BUFFER_OUT;
        }

        cJSON *numOfOsSyscap = cJSON_GetObjectItem(allOsSyscapObj, arrayItemPtr->valuestring);
        uint8_t sectorOfBit = (numOfOsSyscap->valueint) / BITS_OF_BYTE;
        uint8_t posOfBit = (numOfOsSyscap->valueint) % BITS_OF_BYTE;
        if (sectorOfBit >= MAX_OS_SYSCAP_NUM / BITS_OF_BYTE) {
            PRINT_ERR("num of \"os syscap\" is out of 960\n");
            ret = -1;
            goto FREE_PCID_BUFFER_OUT;
        }
        PCIDBuffer->osSyscap[sectorOfBit] |= 1 << (posOfBit);
    }

    char *ptrPriSyscapPos = (char *)(PCIDBuffer + 1);
    for (int32_t i = 0; i < privateCapSize; i++) {
        arrayItemPtr = cJSON_GetArrayItem(privateCapPtr, i);
        char *tmpPtrPriSyscapPos = ptrPriSyscapPos + strlen(arrayItemPtr->valuestring) + 1;
        if ((PCIDMain *)tmpPtrPriSyscapPos > PCIDBuffer + \
                sizeof(PCIDMain) + privateCapSize * PER_SYSCAP_LEN_MAX) {
            break;
        } else {
            ret = memcpy_s(ptrPriSyscapPos, SINGLE_FEAT_LENGTH, \
                           arrayItemPtr->valuestring, strlen(arrayItemPtr->valuestring));
            if (ret != 0) {
                PRINT_ERR("context of \"pri\" array is invaild\n");
                ret = -1;
                goto FREE_PCID_BUFFER_OUT;
            }
            ptrPriSyscapPos += strlen(arrayItemPtr->valuestring) + 1;
        }
    }
    
    cjsonObjectPtr = cJSON_GetObjectItem(cjsonObjectRoot, "api_version");
    if (cjsonObjectPtr == NULL || !cJSON_IsNumber(cjsonObjectPtr)) {
        PRINT_ERR("get \"api_version\" failed, cjsonObjectPtr = %p\n", cjsonObjectPtr);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }
    PCIDBuffer->apiVersion = HtonsInter((uint16_t)cjsonObjectPtr->valueint);
    PCIDBuffer->apiVersionType = 0;

    cjsonObjectPtr = cJSON_GetObjectItem(cjsonObjectRoot, "system_type");
    if (cjsonObjectPtr == NULL || !cJSON_IsString(cjsonObjectPtr)) {
        PRINT_ERR("get \"system_type\" failed, cjsonObjectPtr = %p\n", cjsonObjectPtr);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }
    systemType = cjsonObjectPtr->valuestring;
    PCIDBuffer->systemType = !strcmp(systemType, "mini") ? 0b001 :
                          (!strcmp(systemType, "small") ? 0b010 :
                          (!strcmp(systemType, "standard") ? 0b100 : 0));
    if (PCIDBuffer->systemType == 0) {
        PRINT_ERR("\"system_type\" is invaild, systemType = \"%s\"\n", systemType);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }

    cjsonObjectPtr = cJSON_GetObjectItem(cjsonObjectRoot, "manufacturer_id");
    if (cjsonObjectPtr == NULL || !cJSON_IsNumber(cjsonObjectPtr)) {
        PRINT_ERR("get \"manufacturer_id\" failed, cjsonObjectPtr = %p\n", cjsonObjectPtr);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }
    PCIDBuffer->manufacturerID = HtonlInter((uint32_t)cjsonObjectPtr->valueint);

    cjsonObjectPtr = cJSON_GetObjectItem(cjsonObjectRoot, "product");
    if (cjsonObjectPtr == NULL || !cJSON_IsString(cjsonObjectPtr)) {
        PRINT_ERR("get \"product\" failed, cjsonObjectPtr = %p\n", cjsonObjectPtr);
        ret = -1;
        goto FREE_CONVERT_OUT;
    }

    ret = strncpy_s(productName, NAME_MAX, cjsonObjectPtr->valuestring, strlen(cjsonObjectPtr->valuestring));
    if (ret != 0) {
        PRINT_ERR("strncpy_s failed, source string:%s, len = %d, errno = %d\n",
                  cjsonObjectPtr->valuestring, (int32_t)strlen(cjsonObjectPtr->valuestring), errno);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }

    ret = strncat_s(productName, NAME_MAX, ".sc", 4); // 4. '.' 's' 'c' '\0'
    if (ret != 0) {
        PRINT_ERR("strncat_s failed, (%s, %d, \".sc\", 4), errno = %d\n", productName, NAME_MAX, errno);
        ret = -1;
        goto FREE_PCID_BUFFER_OUT;
    }
    productName[NAME_MAX - 1] = '\0';
    ret = ConvertedContextSaveAsFile(outDirPath, productName, (char *)PCIDBuffer, PCIDBufferLen);
    if (ret != 0) {
        PRINT_ERR("ConvertedContextSaveAsFile failed, outDirPath:%s, filename:%s\n", outDirPath, productName);
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