package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	//should we derreferance it?
	Priv *userlib.PrivateKey

	//Modified to type[]byte
	Signature_Id []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
    //NOTE: If time allows, store user struct and HMAC as:
    // "users_"||SHA256(Kgen) : IV||E(struct)||HMAC(E(struct))

	//var userdata User

	// 1. Generate RSA key-pair
	Kpriv, _ := userlib.GenerateRSAKey()
	Kpubl := &Kpriv.PublicKey

	//2. Generate Kgen, IV, and signature_id using Argon2 (salt=password).
	//Key length(36) : 16 bytes (key), 16 bytes (IV), 4 bytes (signature -- ID)
	Fields_Generate := userlib.Argon2Key([]byte(password), []byte(username), 36)
	Kgen := Fields_Generate[:16]
	IV := Fields_Generate[16:32]
	signature := Fields_Generate[32:]

	// 3. Fill in struct (signature_id should be a random string)
	var userdata = User{Username: username, Password: password, Priv: Kpriv, Signature_Id: signature}

	// 4. Encrypt struct with CFB (key=Kgen, IV=random string)
	// Marshall User before encrypt
	user_, _ := json.Marshal(userdata)

	Encrypted_User := cfb_encrypt(Kgen, user_, IV)

	// 5. Concat IV||E(struct)
	IV_EncryptedStruct := append(IV, Encrypted_User...)

	// 6. Put "signatures_"||signature_id -> HMAC(K_gen, IV||E(struct) into DataStore
	user_data_store := "signatures_" + string(signature[:])
	mac := userlib.NewHMAC(Kgen)
	mac.Write(IV_EncryptedStruct)
	expectedMAC := mac.Sum(nil)
	userlib.DatastoreSet(user_data_store, expectedMAC)

	// 7. Put "users_"||SHA256(Kgen) -> IV||E(struct) into DataStore
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(Kgen))
	user_lookup_id := "users_" + string(sha256.Sum(nil))
	userlib.DatastoreSet(user_lookup_id, IV_EncryptedStruct)

	// 8. Store RSA public key into KeyStore
	userlib.KeystoreSet(username, *Kpubl)

	// 9. Return pointer to the struct
	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	// 1. Reconstruct Kgen using Argon2
	bytes_generated := userlib.Argon2Key([]byte(password), []byte(username), 36)
	Kgen := bytes_generated[:16]

	// 2. Look up "users_"||SHA256(Kgen) in the DataStore and get the E(struct)||IV
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(Kgen))
	user_lookup_id := "users_" + string(sha256.Sum(nil))
	IV_EncryptedStruct, ok := userlib.DatastoreGet(user_lookup_id)

	// 3. If the id is not found in the DataStore, fail with an error
	if !ok {
		return nil, errors.New("Incorrect username or password.")
	}

	// 4. Break up IV||E(struct) and decrypt the structure using Kgen
	IV := IV_EncryptedStruct[:16]
	E_struct := IV_EncryptedStruct[16:]

	//Decrypt then unmarshall data then get ID field
	struct_marshall := cfb_decrypt(Kgen, E_struct, IV)
	var userStruct User
	json.Unmarshal(struct_marshall, &userStruct)

	// 5. Look up "signatures_"||struct->signature_id from the DataStore and
	// get the Signature_HMAC
	id := userStruct.Signature_Id
	id_to_lookup := "signatures_" + string(id)
	signature_hmac, ok := userlib.DatastoreGet(id_to_lookup)

	if !ok {
		return nil, errors.New("HMAC was not found")
	}

	// 6. Verify that HMAC(K_gen, IV||E(struct)) == Signature_HMAC and if not,
	// fail with an error
	mac := userlib.NewHMAC(Kgen)
	mac.Write(IV_EncryptedStruct)
	expectedMAC := mac.Sum(nil)

    // Not sure if this is right way to compare but cannot compare using bytes.equals since cannnot import anything else
	if string(expectedMAC) != string(signature_hmac) { 
		return nil, errors.New("Found corrupted data")
	}

	// 7. Check that username == struct->username and password == struct->password,
	// and if not, fail with an error
	if userStruct.Username != username {
		return nil, errors.New("Wrong username")
	}

	// 8. Return a pointer to the user struct
	return &userStruct, err
}

type File struct {
	Kstruct_encrypt []byte        /// Key to encrypt struct 
	struct_HMACKey []byte         /// Key for HMAC(E(struct))
	file_keyId []byte             /// Key for storing the file in datastore 
	mapkeysToHmacs map[string][]byte
	DataBlocksEncryptKey []byte   /// Key for encrypting data blocks at every append 
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
    //First check that data is not empty, if so then return an error


	//1.Get keys for encrypting the struct, HMAC(E(struct)), 
	//id for storing in dataStore, and for IV 

    // Adding a plus zero in case we have: cs 161 or cs1 61 as paswords
    // And username and same filename 
	argon_input := userdata.Username + "0" 
	argon_keys := userlib.Argon2Key([]byte(argon_input), []byte(filename), 80)

	Kgen_file := argon_keys[:16]
	iv := argon_keys[16:32]
	Hmac_key := argon_keys[32:48]
	file_ID := argon_keys[48:64]
    
    //Note: Maybe I need to generate a UUID in this case
    //Risking having 2 ranges have the same number ID,
    // I have to make it unique 
	key_blocks := argon_keys[64:80]

	//2. Initialize the file struct 
	var keys_to_hmacs = make(map[string][]byte)
	var file_struct = File{Kstruct_encrypt: Kgen_file, struct_HMACKey: Hmac_key, file_keyId: file_ID, mapkeysToHmacs: keys_to_hmacs, DataBlocksEncryptKey: key_blocks}

	//3. Marshall Struct and Encrypt struct 
	file_, _ := json.Marshal(file_struct)

	Encrypted_File := cfb_encrypt(Kgen_file, file_, iv)

	//4. Get the Hmac of the encryption 
	mac := userlib.NewHMAC(Hmac_key)
	mac.Write(Encrypted_File)
	expectedMAC := mac.Sum(nil)

	//5. Concat Hmac(E(struct))||IV||E(struct)
	Mac_IV := append(expectedMAC, iv...)
	MacIV_EncryptedStruct := append(Mac_IV, Encrypted_File...)

	//6. Store in the file 
    userlib.DatastoreSet(string(file_ID), MacIV_EncryptedStruct)
}


// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
 //    /// NOTE: argon(username||counter, password, 32) --> 16:Kmac and 16:iv
 //    /// need to recompute different iv's for every block encryption 

	// // 1. Generate keys and corresponding data to generate argon and get file:
	// argon_input := userdata.Username + "0" 
	// argon_keys := userlib.Argon2Key([]byte(argon_input), []byte(filename), 80)

	// Kgen_file := argon_keys[:16]
	// iv := argon_keys[16:32]
	// Hmac_key := argon_keys[32:48]
	// key_blocks := argon_keys[48:64]	
	// file_ID := argon_keys[64:80]

 //    // 2. Get the file. 
 //    IV_EncryptedStruct, ok := userlib.DatastoreGet(string(file_ID))

 //    // 2.1 If file does not exist return error 
 //    if !ok{
 //    	return errors.New("File not found")
 //    }

 //    // 3. If file exists then break file into Hmac(E(struct))||IV||E(struct)
 //    mac_ := IV_EncryptedStruct[:32]
 //    iv_ := IV_EncryptedStruct[32:48]
 //    E_file := IV_EncryptedStruct[48:]

 //    // 4. Get the mac of the encrypted file
 //    mac := userlib.NewHMAC(Hmac_key)
	// mac.Write(E_file)
	// E_fileMac := mac.Sum(nil)

 //        // 4.1 if data is corrupted then return an error 
	// if string(E_fileMac) != string(mac_) { 
	// 	return errors.New("Found corrupted Mac")
	// }

	//     // 4.2 if data is not corrupted then decrypt the file struct 
	//     // Using the information obtained above from the user 
	// decrypted_file := cfb_decrypt(Kgen_file, E_file, iv)

	//     // 4.3 After decrypting then unmarshall and get the struct
	// var fileStruct File
	// json.Unmarshal(decrypted_file, &fileStruct)

	// // 6. For range of mapkeysToHmacs (cause counter is being increased at the end of append):
	// //	mapkeysToHmacs map[string][]byte
	// for key_string, hmac := range (fileStruct).mapkeysToHmacs {

	//     // Get encrypted data block in datastore using userlib.DatastoreGet(StringMackey)
	//     iv_DataBlock, ok := userlib.DatastoreGet(key_string)
        
 //        /// Just here for debugging purposes. Remove after 
	//     if !ok {
	//     	return errors.New("Could not found value mapped to that key")
	//     }

	//     // Brake the data block into iv and encrypted block 
	//     e_DataBlock := iv_DataBlock[16:]

	//     // convert StringMackey -> key []bytes and get the HMAC of encrypted data block
	//     key_mac := []byte(key_string) //convert from string back to bytes 
	//     _mac := userlib.NewHMAC(key_mac)
	//     _mac.Write(e_DataBlock)
	//     _BlockMac := mac.Sum(nil) 

	//     // Compare this value to HMAC_block
	//     if string(_BlockMac) != string(hmac) {
	//     	return errors.New("Possible corruption found")
	//     }
 //    }
	      
	// // 5. Use Argon to generate Kmac, and iv for data block with: (UUID), salt:username 
	// ///NOte fox problem with UUID ->bytes 
	// uuid_DataBlock := uuid.New()

	// //argon_block := string(count) + userdata.Username
	// key_iv_block := userlib.Argon2Key([]byte(uuid_DataBlock), []byte(userdata.Username), 32)

	// k_block_Hmac := key_iv_block[:16]
	// iv_block := key_iv_block[16:32]

	// // 6. store encrypted block using string(k_block_Hmac): iv||Ecfb((userdata) in datastore //NOTE: Might want to convert
	// // The key to a int not and string since it might produce overhead 
	
	// // Encrypt data block
	// e_DataBlock := cfb_encrypt((fileStruct).DataBlocksEncryptKey, data, iv_block)


	// // Get mac of E(datablock) .... and store it in mapping 
	// _mac := userlib.NewHMAC(k_block_Hmac)
	// _mac.Write(e_DataBlock)
	// _BlockMac := mac.Sum(nil) 

	// (fileStruct).MapkeysToHmacsSet(string(k_block_Hmac), _BlockMac)

	// // Append IV||E(datablock)
	// IV_EDATA := append(iv_block, e_DataBlock...)
    
	// // Store userlib.DataStoreSet()
	// userlib.DatastoreSet(string(k_block_Hmac), IV_EDATA)

	// //7. Encrypt the file struct again ... values changed so we have now different encryption 
	// argon_finput := userdata.Username + "0" 
	// argon_fkeys := userlib.Argon2Key([]byte(argon_finput), []byte(filename), 80)

	// Kgen_ffile := argon_fkeys[:16]
	// iv_f := argon_fkeys[16:32]
	// Hmac_fkey := argon_fkeys[32:48]
	// ffile_ID := argon_fkeys[48:64]
    
 //    //Note: Maybe I need to generate a UUID in this case
 //    //Risking having 2 ranges have the same number ID,
 //    // I have to make it unique 
	// //ffile_ID := argon_fkeys[64:80]

	// Ffile_, _ := json.Marshal(fileStruct)

	// Encrypted_File := cfb_encrypt(Kgen_file, Ffile_, iv_f)

	// //4. Get the Hmac of the encryption 
	// _mac_ := userlib.NewHMAC(Hmac_fkey)
	// _mac_.Write(Encrypted_File)
	// expectedMAC := _mac_.Sum(nil)

	// //5. Concat Hmac(E(struct))||IV||E(struct)
	// Mac_IV := append(expectedMAC, iv...)
	// MacIV_EncryptedStruct := append(Mac_IV, Encrypted_File...)

	// //6. Store in the file 
 //    userlib.DatastoreSet(string(ffile_ID), MacIV_EncryptedStruct)

	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
    /// need to recompute different iv's for every block encryption 

	// 1. Generate keys and corresponding data to generate argon and get file:
    argon_input := userdata.Username + "0" 
	argon_keys := userlib.Argon2Key([]byte(argon_input), []byte(filename), 80)

	Kgen_file := argon_keys[:16]
	iv := argon_keys[16:32]
	Hmac_key := argon_keys[32:48]
	file_ID := argon_keys[48:64]

	//Ommiting getting the key for encypting the data blocks since it has already being stored in file 
    //Note: Maybe I need to generate a UUID in this case
    //Risking having 2 ranges have the same number ID,
    // I have to make it unique 
	//key_blocks := argon_keys[64:80]

    // 2. Get the file. 
    IV_EncryptedStruct, ok := userlib.DatastoreGet(string(file_ID))

    // 2.1 If file does not exist return error 
    if !ok{
    	return nil, errors.New("File not found")
    }

    // 3. If file exists then break file into Hmac(E(struct))||IV||E(struct)
    mac_ := IV_EncryptedStruct[:32]
    iv_ := IV_EncryptedStruct[32:48]
    E_file := IV_EncryptedStruct[48:]

    // 4. Get the mac of the encrypted file
    mac := userlib.NewHMAC(Hmac_key)
	mac.Write(E_file)
	E_fileMac := mac.Sum(nil)

    // 4.1 if data is corrupted then return an error 
	if string(E_fileMac) != string(mac_) { 
		return nil, errors.New("Found corrupted Mac")
	}

	// 4.2 if data is not corrupted then decrypt the file struct 
	// Using the information obtained above from the user 
	decrypted_file := cfb_decrypt(Kgen_file, E_file, iv)

	// 4.3 After decrypting them unmarshall and get the struct
	var fileStruct File
	json.Unmarshal(decrypted_file, &fileStruct)

	// 5. For every data block stored check if data is corrupted if not then store in data variable

	// Create a data variable 
	var data_to_return []byte 

	for key_string, hmac := range (fileStruct).mapkeysToHmacs {
	  	// Get encrypted data block in datastore using userlib.DatastoreGet(StringMackey)
	  	iv_DataBlock, ok := userlib.DatastoreGet(key_string)
        
        /// Just here for debugging purposes. Remove after 
	  	if !ok {
	  		return errors.New("Could not found value mapped to that key")
	    }

	    // Brake the data block into iv and encrypted block 
	    e_DataBlock := iv_DataBlock[16:]
	    iv_data := iv_DataBlock[16:32]

	    // convert StringMackey -> key []bytes and get the HMAC of encrypted data block
	    key_mac := []byte(key_string) //convert from string back to bytes 
	    _mac := userlib.NewHMAC(key_mac)
	    _mac.Write(iv_DataBlock)
	   	_BlockMac := mac.Sum(nil) 

	    // Compare this value to HMAC_block
	   	// If found corrupted data then return nill, error
	    if string(_BlockMac) != string(hmac) {
	    	return nil, errors.New("Data block corrupted")
	   	}

	    // Decrypt data block 
	   	data_decrypted := cfb_decrypt(fileStruct.DataBlocksEncryptKey, e_DataBlock, iv_data) 
	  
	  // append the raw data []bytes to our current data variable 
	   	 data_to_return := append(data_to_return, data_decrypted...)

    }

	 // 6. if none of the data was corrupted then return the data 
	return data_to_return, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	return nil
}

//-------- helper functions --------//
func cfb_encrypt(key []byte, plainText []byte, iv []byte) (cipherText []byte) {
	stream := userlib.CFBEncrypter(key, iv)
	cipherText = make([]byte, len(plainText))
	stream.XORKeyStream(cipherText, plainText)
	return
}

func cfb_decrypt(key []byte, ciphertext []byte, iv []byte) (plaintext []byte) {
	stream := userlib.CFBDecrypter(key, iv)
	plaintext = make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return
}

/// Functions for setting and getting mapkeysToHmacs map[int][]byte 
/// From file struct 
func (filedata *File) MapkeysToHmacsSet(key string, value []byte) {
	foo := make([]byte, len(value))
	copy(foo, value)
	(filedata).mapkeysToHmacs[key] = foo
}

// Returns the value if it exists
func (filedata *File) MapkeysToHmacsGet(key string) (value []byte, ok bool) {
	value, ok = (filedata).mapkeysToHmacs[key]
	if ok && value != nil {
		foo := make([]byte, len(value))
		copy(foo, value)
		return foo, ok
	}
	return
}

// Deletes a key
func (filedata *File) MapkeysToHmacsDelete(key string) {
	delete((filedata).mapkeysToHmacs, key)
}

// Use this in testing to reset the datastore to empty
func (filedata *File) MapkeysToHmacsClear() {
	(filedata).mapkeysToHmacs = make(map[string][]byte)
}

