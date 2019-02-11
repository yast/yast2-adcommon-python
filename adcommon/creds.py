from yast import import_module
import_module('UI')
from yast import *
from subprocess import Popen, PIPE
from samba.credentials import Credentials, MUST_USE_KERBEROS
import re, six
from adcommon.strings import strcasecmp, strncasecmp
import keyring
from samba.net import Net
from samba.credentials import Credentials
from samba.dcerpc import nbt
from shutil import which

def __format_username(username, realm):
    dom, user = ('', '')
    if '\\' in username:
        dom, user = username.split('\\')
    elif '@' in username:
        user, dom = username.split('@')
    else:
        dom, user = (realm, username)
    net = Net(Credentials())
    cldap_ret = net.finddc(domain=dom, flags=(nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS))
    if cldap_ret:
        dom = cldap_ret.dns_domain
    return '%s@%s' % (user, dom.upper())

def kinit_for_gssapi(creds, realm):
    p = Popen([which('kinit'), __format_username(creds.get_username(), realm)], stdin=PIPE, stdout=PIPE)
    p.stdin.write(('%s\n' % creds.get_password()).encode())
    p.stdin.flush()
    return p.wait() == 0

class YCreds:
    def __init__(self, creds, auto_krb5_creds=True):
        self.creds = creds
        self.auto_krb5_creds = auto_krb5_creds
        self.retry = False

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
                    password = UI.QueryWidget('password_prompt', 'Value')
                    save = UI.QueryWidget('remember_prompt', 'Value')
                    UI.CloseDialog()
                    if not password:
                        return False
                    if save:
                        self.__set_keyring(user, password)
                    else:
                        self.__delete_keyring()
                    self.creds.set_username(user)
                    self.creds.set_password(password)
                    return True
                if str(subret) == 'krb_select':
                    user = UI.QueryWidget('krb_select', 'Label')[1:]
                    self.creds.set_username(user)
                    self.__validate_kinit()
                    if self.creds.get_kerberos_state() == MUST_USE_KERBEROS:
                        UI.CloseDialog()
                        return True
                if str(subret) == 'creds_cancel':
                    UI.CloseDialog()
                    return False
                if str(subret) == 'username_prompt':
                    user = UI.QueryWidget('username_prompt', 'Value')
                    dom = ''
                    if '\\' in user:
                        dom, user = user.split('\\')
                    elif '@' in user:
                        user, dom = user.split('@')
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
            return None, None, None
        user, realm = m[0]
        return user, realm, expired

    def __set_keyring(self, user, password):
        keyring.set_password('adcommon', 'username', user)
        keyring.set_password('adcommon', user, password)

    def __delete_keyring(self):
        keyring_user = keyring.get_password('adcommon', 'username')
        try:
            keyring.delete_password('adcommon', 'username')
        except keyring.errors.PasswordDeleteError:
            pass
        try:
            keyring.delete_password('adcommon', keyring_user)
        except keyring.errors.PasswordDeleteError:
            pass

    def __get_keyring(self, user):
        password = None
        keyring_user = keyring.get_password('adcommon', 'username')
        if keyring_user:
            user = keyring_user
        if user:
            password = keyring.get_password('adcommon', user)
        if not user:
            user = ''
        if not password:
            password = ''
        return user, password

    def __password_prompt(self, user):
        user, password = self.__get_keyring(user)
        disp_user, dom = (user, '')
        if '\\' in user:
            dom, disp_user = user.split('\\')
        elif '@' in user:
            disp_user, dom = user.split('@')
        krb_selection = Empty()
        if self.auto_krb5_creds:
            krb_user, krb_realm, krb_expired = self.__recommend_user()
            if not (strcasecmp(disp_user, krb_user) and strncasecmp(dom, krb_realm, min(len(dom), len(krb_realm))) and password):
                if krb_user and not krb_expired:
                    krb_selection = Frame('', VBox(
                        VSpacing(.5),
                        Left(PushButton(Id('krb_select'), Opt('hstretch', 'vstretch'), krb_user)),
                        Left(Label(b'Domain: %s' % krb_realm))
                    ))
                elif krb_user and krb_expired:
                    user = krb_user
        return MinWidth(30, HBox(HSpacing(1), VBox(
            VSpacing(.5),
            Left(Label('To continue, type an administrator password')),
            Frame('', VBox(
                Left(TextEntry(Id('username_prompt'), Opt('hstretch', 'notify'), 'Username', user)),
                Left(Password(Id('password_prompt'), Opt('hstretch'), 'Password', password)),
                HBox(
                    HWeight(1, Left(Label('Domain:'))),
                    HWeight(4, Left(Label(Id('domain'), Opt('hstretch'), dom))),
                ),
                Left(CheckBox(Id('remember_prompt'), 'Remember my credentials', True if user and password else False)),
            )),
            krb_selection,
            Right(HBox(
                PushButton(Id('creds_ok'), 'OK'),
                PushButton(Id('creds_cancel'), 'Cancel'),
            )),
            VSpacing(.5)
        ), HSpacing(1)))

