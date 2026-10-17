"""Public output uses an allowlist; local runtime records retain their schema."""

STAGES = {
    'failure_guard': '初始化保护',
    'agreement_and_update': '启动窗口处理',
    'startup_gate': '启动状态设置',
    'main_pointer_guard': '运行状态保护',
    'native_completion': '主界面初始化',
    'scan_parameters': '识别参数设置',
}


def public_result(result):
    known = {'compatible', 'reused_existing_ready_process', 'failed'}
    status = result.get('status')
    if result.get('diagnostic') == 'passed':
        return {'status': 'diagnostic_passed', 'worker_checks': len(result.get('worker_checks', []))}
    if status not in known:
        status = 'ready' if result.get('ready') else 'completed'
    output = {'status': status}
    identity = result.get('target_identity') or result.get('target')
    if isinstance(identity, dict) and identity.get('profile_id') in ('v248', 'v253'):
        output['version'] = {'v248': 'V2.4.8', 'v253': 'V2.5.3'}[identity['profile_id']]
    if isinstance(result.get('pid'), int):
        output['pid'] = result['pid']
    if result.get('ready') or status == 'reused_existing_ready_process':
        output['ready'] = True
    return output


def public_error(error):
    """Return only fixed text; exception strings can contain paths and contacts."""
    raw = str(error)
    mappings = (
        ('已取消 Windows', 'E_CANCEL', '已取消管理员权限确认，软件尚未启动。'),
        ('缺少本助手', 'E_EXISTING', '已有窗口缺少完整启动记录，已保留。请保存棋局并自行关闭该窗口后重试。'),
        ('多个软件实例', 'E_MULTIPLE', '已有多个软件窗口，均已保留。请整理窗口后重试。'),
        ('正在运行', 'E_BUSY', '启动助手正在运行，请等待完成。'),
        ('构建不匹配', 'E_VERSION', '所选程序与当前支持版本不匹配，请选择支持的主 ChessShark.exe。'),
        ('关键布局不匹配', 'E_VERSION', '所选程序的代码布局尚未适配，请选择支持的主 ChessShark.exe。'),
        ('请选择完整', 'E_TARGET', '请选择完整软件目录中的主 ChessShark.exe。'),
        ('x64', 'E_PLATFORM', '此版本需要 Windows 10/11 x64。'),
        ('日志目录不可写', 'E_DATA', '数据目录不可写，请选择可写位置或用 --data-dir 指定。'),
        ('内嵌文件校验失败', 'E_BUNDLE', '程序文件校验失败，请重新解压完整发布包。'),
        ('路径不可读', 'E_ACCESS', '现有窗口信息读取失败，请以与目标相同的权限运行助手。'),
        ('状态与记录不符', 'E_STATE', '现有窗口状态与完成记录不符，已保留。'),
        ('参数与完成记录不符', 'E_STATE', '现有窗口参数与完成记录不符，已保留。'),
    )
    for marker, code, message in mappings:
        if marker in raw:
            return {'status': 'failed', 'code': code, 'message': message}
    if isinstance(error, FileNotFoundError):
        code, message = 'E_FILE', '未找到所需文件，请重新选择完整软件目录。'
    elif isinstance(error, PermissionError):
        code, message = 'E_ACCESS', '文件或进程访问被拒绝，请检查权限与文件占用。'
    else:
        code, message = 'E_START', '启动未完成，现有窗口已保留。请查看本机助手数据目录中的运行记录。'
        for stage, label in STAGES.items():
            if raw.startswith(stage + ' failed'):
                message = label + '未完成，现有窗口已保留。请查看本机运行记录。'
                break
    return {'status': 'failed', 'code': code, 'message': message}
