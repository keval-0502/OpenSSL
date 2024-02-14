#!/bin/bash

# Check the number of arguments
if [[ "$#" -lt 5 ]]; then
    echo "ERROR bavisi.ke --------Incorrect arguments: Expected input in the format ./crypto.sh -sender receiver1.pub receiver2.pub receiver3.pub sender.priv <plaintext_file> <zip_file>" >&2
    echo "ERROR bavisi.ke" >&2
    exit 1
fi

# Check if the files passed in the argument exist or not
if [[ -f $2 ]] && [[ -f $3 ]] && [[ -f $4 ]] && [[ -f $5 ]] && [[ -f $6 ]]; then
    echo "ALl the files passed as arguments exists. Proceeding......"
else 
    echo "ERROR bavisi.ke ------ Error in the number of files passed as arguments or the files do not exist" >&2
fi

# Determine if sender or receiver operation
operation=$1

# Sender's side
if [ "$operation" == "-sender" ]; then

    #make a temp directory to store intermediate files
    mkdir tempfiles 2> /dev/null

    # To geneate session key to encrypt the file
    openssl rand -base64 128 > tempfiles/session.key

    # Encrypt the file
    openssl enc -aes-256-cbc -pbkdf2 -e -in $6 -out tempfiles/encryptedfile.enc -pass file:tempfiles/session.key

    # Sign the file
    openssl dgst -sha256 -sign $5 -out tempfiles/encryptedfile.sign tempfiles/encryptedfile.enc

    # generate shared secret keys for each receivers
    openssl pkeyutl -derive -inkey $5 -peerkey $2 -out tempfiles/ssr1
    openssl pkeyutl -derive -inkey $5 -peerkey $3 -out tempfiles/ssr2
    openssl pkeyutl -derive -inkey $5 -peerkey $4 -out tempfiles/ssr3

    # encrypt the session keys with shared secret for each receiver
    openssl enc -aes-256-cbc -pbkdf2 -e -in tempfiles/session.key -out tempfiles/sessionr1.key_enc -pass file:tempfiles/ssr1
    openssl enc -aes-256-cbc -pbkdf2 -e -in tempfiles/session.key -out tempfiles/sessionr2.key_enc -pass file:tempfiles/ssr2
    openssl enc -aes-256-cbc -pbkdf2 -e -in tempfiles/session.key -out tempfiles/sessionr3.key_enc -pass file:tempfiles/ssr3

    # Combine encrypted file and signature into zip file
    zip -j $7 tempfiles/encryptedfile.enc tempfiles/encryptedfile.sign tempfiles/sessionr1.key_enc tempfiles/sessionr2.key_enc tempfiles/sessionr3.key_enc

    #check if the zip file was created or not
    if [[ -f $7 ]]; then
        echo "The Zip file has been successfully created"
        rm -rf tempfiles
    else
        echo "ERROR bavisi.ke ------- Error in creating the Zip file" >&2
        rm -rf tempfiles
    fi


# Receiver's side
elif [ "$operation" == "-receiver" ]; then

    #make a temp directory to store intermediate files
    mkdir tempfiles_r > /dev/null

	# check if the zip file has enough files or not
    if [[ $(unzip -l $4 | tail -n 1 | awk {'print $2'}) = '5' ]]; then
        echo "Zip file contains the expected amount of files"
    else
        echo "ERROR bavisi.ke -------- Less file detected while unzipping than expected" >&2
        exit
    fi

    #unzipping the file
	unzip -o $4 -d tempfiles_r > /dev/null

	# Verify the signature using the provided public key
	if [[ $(openssl dgst -sha256 -verify $3 -signature tempfiles_r/encryptedfile.sign tempfiles_r/encryptedfile.enc) = 'Verified OK' ]]; then
    	echo "Signature verification successful"
	else
    	echo "ERROR bavisi.keval ----------- Signature verification failed" >&2
    	exit 1
    fi

    #creating shared secret key on the receiver end
    openssl pkeyutl -derive -inkey $2 -peerkey $3 -out tempfiles_r/ssr_receiver

    #trying the decrypt the encrypted random symmetric session key with the generated shared secret
    openssl enc -aes-256-cbc -pbkdf2 -d -in tempfiles_r/sessionr1.key_enc -out tempfiles_r/potentialrsskey_decrypted.1 -pass file:tempfiles_r/ssr_receiver

    openssl enc -aes-256-cbc -pbkdf2 -d -in tempfiles_r/sessionr2.key_enc -out tempfiles_r/potentialrsskey_decrypted.2 -pass file:tempfiles_r/ssr_receiver

    openssl enc -aes-256-cbc -pbkdf2 -d -in tempfiles_r/sessionr3.key_enc -out tempfiles_r/potentialrsskey_decrypted.3 -pass file:tempfiles_r/ssr_receiver

    #Check if the digital envelope was decrypted using the generated shared secret key or not
    rsskey_decrypted=0
    if [[ $(file tempfiles_r/potentialrsskey_decrypted.1) =~ "ASCII text" ]]; then
        rsskey_decrypted=1
        decrypted_rsskey_filepath=tempfiles_r/potentialrsskey_decrypted.1
    elif [[ $(file tempfiles_r/potentialrsskey_decrypted.2) =~ "ASCII text" ]]; then
        rsskey_decrypted=1
        decrypted_rsskey_filepath=tempfiles_r/potentialrsskey_decrypted.2
    elif [[ $(file tempfiles_r/potentialrsskey_decrypted.3) =~ "ASCII text" ]]; then
        rsskey_decrypted=1
        decrypted_rsskey_filepath=tempfiles_r/potentialrsskey_decrypted.3
    fi

    #If random symmetric session key was decrypted, decrypt the text file otherwise print error message.
    if [[ $rsskey_decrypted = 1 ]]; then
        echo "symmetric Key Decrypted successfully"
        openssl enc -aes-256-cbc -pbkdf2 -d -in tempfiles_r/encryptedfile.enc -out $5 -pass file:$decrypted_rsskey_filepath
        echo "Decrypted the Encrypted text file as well"
        rm -rf tempfiles_r
    else
        echo "ERROR bavisi.ke -------- Digital Envelope Decryption failed. Private key provided cannot access any envelopes" >&2
        rm -rf tempfiles_r
        exit
    fi

# Error message for invalid operating mode.
else
    echo "ERROR bavisi.ke Incorrect Mode Specified" >&2
fi