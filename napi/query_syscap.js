// 首先需要通过requireInternal函数加载本模块
const systemCapability = requireInternal('systemCapability');

// 这里定义了模块对外暴露的所有api
export default {
    querySystemCapabilities: systemCapability.querySystemCapabilities
}