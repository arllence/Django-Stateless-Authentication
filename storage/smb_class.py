from smb.SMBConnection import SMBConnection
from smb.SMBHandler import SMBHandler
from django.conf import settings


class SMBSTORAGEUTILITY:
    def __init__(self):
        storage_settings = settings.SMB_STORAGE_OPTIONS
        self.network_username = settings.SMB_STORAGE_OPTIONS['username']
        self.network_password = storage_settings['password']
        self.network_host = storage_settings['host']
        self.share_name = settings.SMB_STORAGE_OPTIONS['share_name']
        self.server_name = storage_settings['server_name']
        self.client_machine = storage_settings['client_machine']
        self.timeout = storage_settings['timeout']
        pass

    def create_smb_connection(self):
        storage_settings = settings.SMB_STORAGE_OPTIONS
        # if not storage_settings:
        #     return False
        # else:
        self.network_username = settings.SMB_STORAGE_OPTIONS['username']
        self.network_password = storage_settings['password']
        self.network_host = storage_settings['host']
        self.share_name = settings.SMB_STORAGE_OPTIONS['share_name']
        self.server_name = storage_settings['server_name']
        self.client_machine = storage_settings['client_machine']
        self.timeout = storage_settings['timeout']

        self.smb_connection = SMBConnection(
            self.network_username, self.network_password, "", "", use_ntlm_v2=True)
        self.smb_connection_status = self.smb_connection.connect(
            self.network_host, 445)
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", self.smb_connection)
        return self.smb_connection

    def get_connection_status(self, smb_connection):
        connection_status = self.create_smb_connection()
        if connection_status:
            return True
        else:
            return False

    def createNewDirectory(self, directory_name):
        established_smb_connection = self.create_smb_connection()
        create_dir = established_smb_connection.createDirectory(
            share_name, directory_name)
        return True

    def deleteDirectory(self, directory_name):
        established_smb_connection = self.create_smb_connection()
        create_dir = established_smb_connection.deleteDirectory(
            share_name, directory_name, self.timeout)
        return True

    def uploadFile(self, file_object, folder_name, file_name):
        file_details = "{} /{}".format(folder_name, file_name)
        # print(file_details)
        file_details = "media/out/local.py"
        # established_smb_connection = self.create_smb_connection()
        # print("doc details",established_smb_connection)
        conn = SMBConnection("peterson", "localhost", "", "", use_ntlm_v2=True)
        conn_status = conn.connect("192.168.214.143", 445)
        # print("uploaded file",self.server_name)
        # conn.storeFile(self.server_name,"media/out/local.py",file_object)
        localFile = 'test.txt'
        with open(localFile, 'rb') as file:
            print(file)
            # conn.storeFile(self.server_name,"media/out/local.py",file)
        # upload_status = conn.storeFile(self.server_name,file_details,file_object)
        # if upload_status:
        #     return True
        # else:
        #     return False
        # with open(localFile, 'rb') as file:
        #     conn.storeFile(service_name,"media/out/local.py",file)

