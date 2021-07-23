import tempfile
from smb.SMBConnection import SMBConnection
import  urllib.request 
import os
import tempfile
from smb.SMBHandler import SMBHandler
from django.conf import settings
smb_settings = settings.SMB_STORAGE_OPTIONS

def store_file(file_object,document_name):
    
    # server_ip = "192.168.214.143" # Take your server IP - I have put a fake IP :)
    # server_name = 'DiskStation2' # The servername for the IP above
    # share_name = "volume1" # This is the principal folder of your network that you want's to connect
    # network_username = 'peterson' # This is your network username
    # network_password = 'localhost' # This is your network password
    # machine_name = 'africancoder' # Your machine name

    server_ip = smb_settings['host']# Take your server IP - I have put a fake IP :)
    server_name = smb_settings['server_name'] # The servername for the IP above
    share_name = smb_settings['share_name']# This is the principal folder of your network that you want's to connect
    network_username = smb_settings['username'] # This is your network username
    network_password = smb_settings['password'] # This is your network password
    machine_name = smb_settings['client_machine'] 
    
    # conn = SMBConnection(network_username, network_password, machine_name, server_name, use_ntlm_v2 = True)
    conn=SMBConnection(network_username,network_password,"","",use_ntlm_v2 = True)
    conn_status = conn.connect(server_ip, 445)
    
    # conn_status = conn.connect(server_ip, 139)
    # print(result)
    


    if conn_status is True:
        service_name = smb_settings['service_name'] 
        # path = '/volume1/EDMS/media/'
        # path = '/volume1/EDMS/media/'
        # create_dir = conn.createDirectory(service_name,'peterson_test')
        # remove_dir = conn.deleteDirectory(service_name,'peterson_test',timeout=30)
        # watermarked_pdf = 'smb_files.py'
        # file_data = open(watermarked_pdf,'rb')
        
        # filelist = conn.listPath(service_name,'/')
        # for f in filelist:
        #         print(f.filename)
        # # retrieve url
        # sheet_to_download = open('valuation.pdf','wb')

        # retrivening file
        # with open('local_file.pdf', 'wb') as fp:
        #     # conn.retrieveFile('share', '/path/to/remote_file', fp)
        #     retrieve_file =conn.retrieveFile(service_name,'media/out/valuation.pdf',fp)
        #     fp.close()
        # localFile = '/opt/edms/deployment.sh'
        # with open(localFile, 'rb') as file:
   
        conn.storeFile(service_name,smb_settings['file_path']+"{}".format(document_name),file_object)
        conn.close()

# def retrieve_file(document_name):
#     server_ip = "192.168.214.143" # Take your server IP - I have put a fake IP :)
#     server_name = 'DiskStation2' # The servername for the IP above
#     share_name = "volume1" # This is the principal folder of your network that you want's to connect
#     network_username = 'peterson' # This is your network username
#     network_password = 'localhost' # This is your network password
#     machine_name = 'africancoder' # Your machine name
#     # conn = SMBConnection(network_username, network_password, machine_name, server_name, use_ntlm_v2 = True)
#     conn=SMBConnection(network_username,network_password,"","",use_ntlm_v2 = True)
#     conn_status = conn.connect(server_ip, 445)
#     # conn_status = conn.connect(server_ip, 139)
#     # print(result)


#     if conn_status is True:
#         service_name = 'EDMS'
#         # path = '/volume1/EDMS/media/'
#         # path = '/volume1/EDMS/media/'
#         # create_dir = conn.createDirectory(service_name,'peterson_test')
#         # remove_dir = conn.deleteDirectory(service_name,'peterson_test',timeout=30)
#         # watermarked_pdf = 'smb_files.py'
#         # file_data = open(watermarked_pdf,'rb')
#         path = '/volume1/EDMS/media/in/'
#         # filelist = conn.listPath(service_name,'/')
#         # for f in filelist:
#         #         print(f.filename)
#         # # retrieve url
#         # sheet_to_download = open('valuation.pdf','wb')

#         # retrivening file
#         # with open('local_file.pdf', 'wb') as fp:
#         #     # conn.retrieveFile('share', '/path/to/remote_file', fp)
#         #     retrieve_file =conn.retrieveFile(service_name,'media/out/valuation.pdf',fp)
#         #     fp.close()
#         # localFile = '/opt/edms/deployment.sh'
#         # with open(localFile, 'rb') as file:
        
#         director = urllib.request.build_opener(SMBHandler)
#         print(director)
#         # print('smb://peterson:localhost@192.168.214.143/EDMS/'+ "media/out/{}".format(document_name))
#         fh = director.open(u'smb://peterson:localhost@192.168.214.143/EDMS/'+ "media/out/{}".format(document_name))
#         # print(fh.read())
#         try:
#             tmp = tempfile.NamedTemporaryFile(delete=False)
#             with open(tmp.name, 'w') as fi:
#                 tmp.write(fh.read())
#                 # write to your tempfile, mode may vary
#             response = open(tmp.name, 'rb')
#             print("attribut",response)
#             return response
#         finally:
#             pass
#             # os.remove(tmp.name)
#             # fh.close()
        



#     # print(conn_status)
#     # file_attributes, filesize = conn.retrieveFile('smbtest', '/rfc1001.txt', file_obj)
#     # files = conn.listPath(share_name, "/volume1/EDMS/media/")
#     # for item in files:
#     #    print(item.filename)


# # import urllib
# # from smb.SMBHandler import SMBHandler
# # opener = urllib.request.build_opener(SMBHandler)
# # fh = opener.open('smb://host/share/file.txt')
# # data = fh.read()
# # fh.close()