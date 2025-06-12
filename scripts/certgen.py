import httpe_core.httpe_cert as httpe_cert
import httpe_core.httpe_keys as httpe_keys

import os
def main():

    httpe_cert.create_pem_files()
    if(os.path.exists("private_key.pem") == True):
        print("Successfully created private_key.pem")
        print("This file is used to sign the certificate")
    else:
        print("Failed to create private_key.pem")
    if(os.path.exists("public.pem") == True):
        print("Successfully created public.pem. Put this in the root dir of your httpe client")
        print("This file is used to verify certificate by the client")
    else:
        print("Failed to create public.pem")
    httpe_keys.save_keys_rsa_keys()
    if(os.path.exists("private_key.edoi") == True):
        print("Successfully created private_key.edoi. Put this in the root dir of your httpe_server")
    else:
         print("Failed to create private_key.edoi")
    if(os.path.exists("public_key.edoi") == True):
        print("Successfully created public_key.edoi. Put this in the root dir of your httpe server")
    else:
        print("Failed to create public_key.edoi")
    
    
    httpe_cert.create_corticate(save=True)
    if(os.path.exists("cert.ctre") == True):
        print("Successfully created cert.ctre. Put this in the root dir of your httpe server")
        print("This is your servers self signed certificate")
    else:
        print("Failed to create cert.ctre")
    

    print("All files are created. Please put them in there designated locations.")
    print("Warning:\n\t-cert.ctre is mapped to localhost and is valid for 100 days\n\t-The code MIGHT fail silently if the files are placed incorrectly.\n\t-You CANNOT change the locations where the library looks for the needed files. This should change soon.")


main()