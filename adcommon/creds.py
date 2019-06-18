from yast import import_module
import_module('UI')
from yast import *
from subprocess import Popen, PIPE
from samba.credentials import Credentials, MUST_USE_KERBEROS
import re, six
from adcommon.strings import strcasecmp, strncasecmp
from samba.net import Net
from samba.credentials import Credentials
from samba.dcerpc import nbt
from shutil import which
from samba import NTSTATUSError
from tempfile import NamedTemporaryFile
import os

cldap_ret = None

def __cldap_fill(dom):
    global cldap_ret
    if not cldap_ret or not strcasecmp(dom, cldap_ret.dns_domain):
        net = Net(Credentials())
        cldap_ret = net.finddc(domain=dom, flags=(nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS | nbt.NBT_SERVER_WRITABLE))

def __validate_dom(dom):
    global cldap_ret
    __cldap_fill(dom)
    return cldap_ret.dns_domain if cldap_ret else None

def pdc_dns_name(dom):
    global cldap_ret
    __cldap_fill(dom)
    return cldap_ret.pdc_dns_name if cldap_ret else None

def parse_username(username, domain=''):
    dom, user = (domain, username)
    if '\\' in username:
        dom, user = username.split('\\')
    elif '@' in username:
        user, dom = username.split('@')
    return dom, user

def __format_username(username, realm):
    dom, user = parse_username(username, realm)
    cldap_dom = __validate_dom(dom)
    dom = cldap_dom if dom else dom
    return '%s@%s' % (user, dom.upper())

def krb5_temp_conf(realm):
    name = None
    with NamedTemporaryFile(mode='w', delete=False) as k:
        if os.path.exists('/etc/krb5.conf'):
            k.write(open('/etc/krb5.conf', 'r').read())
        k.write('\n[realms]\n%s = {\nkdc = %s\n}' % (realm.upper(), pdc_dns_name(realm)))
        k.flush()
        name = k.name
    return name

def kinit_for_gssapi_try(creds, realm):
    p = Popen([which('kinit'), __format_username(creds.get_username(), realm)], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.stdin.write(('%s\n' % creds.get_password()).encode())
    p.stdin.flush()
    return p

def kinit_for_gssapi(creds, realm):
    p = kinit_for_gssapi_try(creds, realm)
    _, err = p.communicate()
    if p.returncode == 0:
        return True
    else:
        m = re.match(r'kinit: Credential cache directory ([/\w]+) does not exist while getting default ccache', err.decode())
        if m:
            os.makedirs(m.group(1), exist_ok=True)
            p = kinit_for_gssapi_try(creds, realm)
            return p.wait() == 0
    return False

def __msg(msg):
    UI.OpenDialog(Opt('warncolor'), MinWidth(30, HBox(HSpacing(1), VBox(
        VSpacing(0.5),
        Label(msg),
        VSpacing(0.5),
        Right(PushButton(Id('id_ok'), 'OK')),
        VSpacing(0.5),
    ), HSpacing(1))))
    UI.UserInput()
    UI.CloseDialog()

def switch_domains(lp, creds, cred_valid):
    '''Change domains and set the new lp and creds
    param LoadParm      Instance of samba LoadParm
    param Credentials   Instance of samba Credentials
    param condition     A function pointer to call which checks if the creds are valid
    return bool
    '''
    UI.SetApplicationTitle('Change domain')
    dialog = HBox(HSpacing(1), VBox(
        VSpacing(0.5),
        HBox(
            HWeight(1, Left(Label('Domain:'))),
            HWeight(4, Left(TextEntry(Id('domain'), Opt('hstretch'), lp.get('realm')))),
        ),
        VSpacing(0.5),
        Right(HBox(
            PushButton(Id('id_ok'), 'OK'),
            PushButton(Id('id_cancel'), 'Cancel'),
        )),
        VSpacing(0.5),
    ), HSpacing(1))
    UI.OpenDialog(dialog)
    res = False
    while True:
        ret = UI.UserInput()
        if str(ret) == 'id_ok':
            msg = ''
            try:
                dom = __validate_dom(UI.QueryWidget('domain', 'Value'))
            except NTSTATUSError as e:
                msg = e.args[-1]
            if not dom:
                __msg('The domain %s could not be found%s' % (UI.QueryWidget('domain', 'Value'), ' because:\n%s' % msg if msg else '.'))
            else:
                creds.set_password('')
                realm_back = lp.get('realm')
                lp.set('realm', dom.upper())
                ycred = YCreds(creds, auto_krb5_creds=False, possible_save_creds=False)
                res = ycred.Show(cred_valid)
                if not res:
                    lp.set('realm', realm_back)
                break
        elif str(ret) == 'id_cancel':
            break
    UI.CloseDialog()
    return res

class YCreds:
    def __init__(self, creds, auto_krb5_creds=True, possible_save_creds=True):
        self.creds = creds
        self.auto_krb5_creds = auto_krb5_creds
        self.possible_save_creds = possible_save_creds
        # The QT UI conflicts with keyring's dbus somehow
        if UI.HasSpecialWidget('Wizard'):
            self.possible_save_creds = False
        self.retry = False

    def Show(self, cred_valid=None):
        '''Show the Credentials Dialog
        param condition     A function pointer to call which checks if the creds are valid
        return bool
        '''
        got_creds = self.get_creds()
        while got_creds:
            if cred_valid and not cred_valid():
                got_creds = self.get_creds()
                continue
            break
        return got_creds

    def get_creds(self):
        if self.retry:
            self.creds.set_password('')
        self.retry = True
        if not self.creds.get_password():
            UI.SetApplicationTitle('Authenticate')
            UI.OpenDialog(self.__password_prompt(self.creds.get_username()))
            while True:
                subret = UI.UserInput()
                if str(subret) == 'creds_ok':
                    user = UI.QueryWidget('username_prompt', 'Value')
                    dom, user = parse_username(user)
                    if not dom:
                        dom = UI.QueryWidget('domain', 'Value')
                    password = UI.QueryWidget('password_prompt', 'Value')
                    if self.possible_save_creds:
                        save = UI.QueryWidget('remember_prompt', 'Value')
                    UI.CloseDialog()
                    if self.possible_save_creds:
                        if save:
                            self.__set_keyring(user, dom, password)
                        else:
                            self.__delete_keyring()
                    self.creds.set_username(user)
                    self.creds.set_password(password)
                    if dom:
                        self.creds.set_domain(dom)
                    return True
                if str(subret) == 'krb_select':
                    user = UI.QueryWidget('krb_select', 'Label')[1:]
                    self.creds.set_username(user)
                    self.creds.set_domain(UI.QueryWidget('krb_realm', 'Value'))
                    self.__validate_kinit()
                    if self.creds.get_kerberos_state() == MUST_USE_KERBEROS:
                        UI.CloseDialog()
                        return True
                if str(subret) == 'creds_cancel':
                    UI.CloseDialog()
                    return False
                if str(subret) == 'username_prompt':
                    user = UI.QueryWidget('username_prompt', 'Value')
                    dom, user = parse_username(user)
                    UI.ChangeWidget('domain', 'Value', dom)
                    continue
        return True

    def __validate_kinit(self):
        out, _ = Popen(['klist'], stdout=PIPE, stderr=PIPE).communicate()
        m = re.findall(six.b('Default principal:\s*(\w+)@([\w\.]+)'), out)
        if len(m) == 0:
            return None
        user, realm = m[0]
        if not strcasecmp(user, self.creds.get_username()):
            return None
        if Popen(['klist', '-s'], stdout=PIPE, stderr=PIPE).wait() != 0:
            return None
        self.creds.set_kerberos_state(MUST_USE_KERBEROS)

    def __recommend_user(self):
        expired = False
        if Popen(['klist', '-s'], stdout=PIPE, stderr=PIPE).wait() != 0:
            expired = True
        out, _ = Popen(['klist'], stdout=PIPE, stderr=PIPE).communicate()
        m = re.findall(six.b('Default principal:\s*(\w+)@([\w\.]+)'), out)
        if len(m) == 0:
            return '', '', expired
        user, realm = m[0]
        return user, realm, expired

    def __set_keyring(self, user, dom, password):
        from keyring import set_password
        set_password('adcommon', 'username', user)
        set_password('adcommon', 'domain', dom)
        set_password('adcommon', user, password)

    def __delete_keyring(self):
        from keyring import get_password, delete_password, errors
        keyring_user = get_password('adcommon', 'username')
        try:
            delete_password('adcommon', 'username')
        except errors.PasswordDeleteError:
            pass
        try:
            delete_password('adcommon', 'domain')
        except errors.PasswordDeleteError:
            pass
        if keyring_user is not None:
            try:
                delete_password('adcommon', keyring_user)
            except errors.PasswordDeleteError:
                pass

    def __get_keyring(self, user):
        from keyring import get_password, errors
        dom = None
        password = None
        try:
            keyring_user = get_password('adcommon', 'username')
        except (errors.InitError, RuntimeError):
            self.possible_save_creds = False
            return (user, '', '')
        if keyring_user:
            user = keyring_user
        if user:
            dom = get_password('adcommon', 'domain')
            password = get_password('adcommon', user)
        if not user:
            user = ''
        if not password:
            password = ''
        if not dom:
            dom = ''
        return user, dom, password

    def __password_prompt(self, user):
        user, dom, password = self.__get_keyring(user) if self.possible_save_creds else (user, '', '')
        krb_selection = Empty()
        if self.auto_krb5_creds:
            krb_user, krb_realm, krb_expired = self.__recommend_user()
            if not (strcasecmp(user, krb_user) and strncasecmp(dom, krb_realm, min(len(dom), len(krb_realm))) and password):
                if krb_user and not krb_expired:
                    krb_selection = Frame('', VBox(
                        VSpacing(.5),
                        Left(PushButton(Id('krb_select'), Opt('hstretch', 'vstretch'), krb_user)),
                        HBox(
                            HWeight(1, Left(Label('Domain:'))),
                            HWeight(4, Left(Label(Id('krb_realm'), Opt('hstretch'), krb_realm))),
                        ),
                    ))
                elif krb_user and krb_expired:
                    user = krb_user
        return MinWidth(30, HBox(HSpacing(1), VBox(
            VSpacing(.5),
            Left(Label('To continue, type an Active Directory administrator password')),
            Frame('', VBox(
                Left(TextEntry(Id('username_prompt'), Opt('hstretch', 'notify'), 'Username', user)),
                Left(Password(Id('password_prompt'), Opt('hstretch'), 'Password', password)),
                HBox(
                    HWeight(1, Left(Label('Domain:'))),
                    HWeight(4, Left(Label(Id('domain'), Opt('hstretch'), dom))),
                ),
                Left(CheckBox(Id('remember_prompt'), 'Remember my credentials', True if user and password else False)) if self.possible_save_creds else Empty(),
            )),
            krb_selection,
            Right(HBox(
                PushButton(Id('creds_ok'), 'OK'),
                PushButton(Id('creds_cancel'), 'Cancel'),
            )),
            VSpacing(.5)
        ), HSpacing(1)))

