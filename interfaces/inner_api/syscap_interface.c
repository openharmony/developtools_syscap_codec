/*
 * Copyright (C) 2022-2022 Huawei Device Co., Ltd.
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

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <securec.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <securec.h>
#include "create_pcid.h"
#include "syscap_interface.h"

#define PCID_OUT_BUFFER 32
#define MAX_SYSCAP_STR_LEN 128
#define OS_SYSCAP_BYTES 120
#define BITS_OF_BYTE 8
#define PCID_MAIN_LEN 128

#define PRINT_ERR(...) \
    do { \
        printf("ERROR: in file %s at line %d -> ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
    } while (0)

static char *inputFile = "/system/etc/PCID.sc";

static const SyscapWithNum arraySyscap[] = {
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

static uint32_t GetFileContext(char **contextBufPtr, uint32_t *bufferLen)
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

bool EncodeOsSyscap(int **output)
{
    int32_t ret;
    int32_t res;
    char *contextBuffer = NULL;
    int *outputArray = NULL;
    uint32_t bufferLen;

    ret = GetFileContext(&contextBuffer, &bufferLen);
    if (ret != 0) {
        PRINT_ERR("GetFileContext failed, input file : rk3568.sc\n");
        return false;
    }

    outputArray = (int *)malloc(PCID_MAIN_LEN);
    if (outputArray == NULL) {
        PRINT_ERR("malloc buffer failed, size = %d\n", PCID_MAIN_LEN);
        return false;
    }
    (void)memset_s(outputArray, PCID_MAIN_LEN, 0, PCID_MAIN_LEN);

    res = memcpy_s(outputArray, PCID_MAIN_LEN, contextBuffer, PCID_MAIN_LEN);
    if (res != 0) {
        PRINT_ERR("memcpy_s failed.");
        FreeContextBuffer(contextBuffer);
        free(outputArray);
        return false;
    }

    FreeContextBuffer(contextBuffer);
    *output = outputArray;
    return true;
}

bool EncodePrivateSyscap(char **output, int *outputLen)
{
    int32_t ret;
    int32_t res;
    char *contextBuffer = NULL;
    char *outputStr = NULL;
    uint32_t bufferLen;

    ret = GetFileContext(&contextBuffer, &bufferLen);
    if (ret != 0) {
        PRINT_ERR("GetFileContext failed, input file : rk3568.sc\n");
        return false;
    }
    
    *outputLen = bufferLen - MAX_SYSCAP_STR_LEN - 1;
    outputStr = (char *)malloc(*outputLen);
    if (outputStr == NULL) {
        PRINT_ERR("malloc buffer failed, size = %d, errno = %d\n", *outputLen, errno);
        return false;
    }
    (void)memset_s(outputStr, *outputLen, 0, *outputLen);
    res = strncpy_s(outputStr, *outputLen + 1, contextBuffer + MAX_SYSCAP_STR_LEN, *outputLen);
    if (res != 0) {
        PRINT_ERR("strcpy_s failed.");
        FreeContextBuffer(contextBuffer);
        return false;
    }

    FreeContextBuffer(contextBuffer);
    *output = outputStr;
    return true;
}

bool DecodeOsSyscap(int input[32], char (**output)[128], int *outputCnt)
{
    errno_t nRet = 0;
    uint16_t indexOfSyscap[OS_SYSCAP_BYTES * OS_SYSCAP_BYTES] = {0};
    int countOfSyscap = 0, i, j;

    uint8_t *osSyscap = (uint8_t *)(input + 2); // 2, int[2] of pcid header

    for (i = 0; i < OS_SYSCAP_BYTES; i++) {
        for (j = 0; j < BITS_OF_BYTE; j++) {
            if (osSyscap[i] & (0x01 << j)) {
                indexOfSyscap[countOfSyscap++] = i * BITS_OF_BYTE + j;
            }
        }
    }

    *outputCnt = countOfSyscap;
    char (*strSyscap)[MAX_SYSCAP_STR_LEN] = NULL;
    strSyscap= (char (*)[MAX_SYSCAP_STR_LEN])malloc(countOfSyscap * MAX_SYSCAP_STR_LEN);
    if (strSyscap == NULL) {
        PRINT_ERR("malloc failed.");
        *outputCnt = 0;
        return false;
    }
    (void)memset_s(strSyscap, countOfSyscap * MAX_SYSCAP_STR_LEN, \
                   0, countOfSyscap * MAX_SYSCAP_STR_LEN);
    char **strSyscapBak = (char **)strSyscap;

    for (i = 0; i < countOfSyscap; i++) {
        for (j = 0; j < sizeof(arraySyscap) / sizeof(SyscapWithNum); j++) {
            if (arraySyscap[j].num == indexOfSyscap[i]) {
                nRet = strcpy_s(*strSyscap, MAX_SYSCAP_STR_LEN, arraySyscap[j].syscapStr);
                if (nRet != EOK) {
                    printf("strcpy_s failed. error = %d\n", nRet);
                    *outputCnt = 0;
                    free(strSyscap);
                    return false;
                }
                strSyscap++;
                break;
            }
        }
    }

    *output = (char (*)[MAX_SYSCAP_STR_LEN])strSyscapBak;
    return true;
}

bool DecodePrivateSyscap(char *input, char (**output)[128], int *outputCnt)
{
    char (*outputArray)[MAX_SYSCAP_STR_LEN] = NULL;
    char *inputStr = input;
    uint16_t bufferLen;
    int syscapCnt = 0, ret;

    while (*inputStr != '\0') {
        if (*inputStr == ',') {
            syscapCnt++;
        }
        inputStr++;
    }
    inputStr = input;

    bufferLen = MAX_SYSCAP_STR_LEN * syscapCnt;
    outputArray = (char (*)[MAX_SYSCAP_STR_LEN])malloc(bufferLen);
    if (outputArray == NULL) {
        PRINT_ERR("malloc buffer failed, size = %d, errno = %d\n", bufferLen, errno);
        syscapCnt = 0;
        return false;
    }
    (void)memset_s(outputArray, bufferLen, 0, bufferLen);
    char **outputArrayBak = (char **)outputArray;
    char priSyscapStr[MAX_SYSCAP_STR_LEN - 17] = {0}; // 17. size of "SystemCapability."
    char *tempPriSyscapStr = priSyscapStr;
    while (*inputStr != '\0') {
        if (*inputStr == ',') {
            *tempPriSyscapStr = '\0';
            ret = sprintf_s(*outputArray, MAX_SYSCAP_STR_LEN, "SystemCapability.%s", priSyscapStr);
            if (ret == -1) {
                PRINT_ERR("sprintf_s failed\n");
                *outputCnt = 0;
                free(outputArray);
                return false;
            }
            tempPriSyscapStr = priSyscapStr;
            outputArray++;
            inputStr++;
            continue;
        }
        *tempPriSyscapStr++ = *inputStr++;
    }

    *outputCnt = syscapCnt;
    *output = (char (*)[MAX_SYSCAP_STR_LEN])outputArrayBak;
    return true;
}