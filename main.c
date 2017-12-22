#include <stdlib.h>
#include <curl/curl.h>
#include "blkmaker.h"
#include "blkmaker_jansson.h"
#include <mpi.h>
#include <stdio.h>
#include <gcrypt.h>
#include <libbase58.h>
#include <assert.h>
#include "input.c"
struct string {
  char *ptr;
  size_t len;
};

const uint32_t MAX_CACULATE = 0x00002710; //max number of hash that slaves have to caculate
///
///Init struct to save response from server
///
void init_string(struct string *s) {
  s->len = 0;
  s->ptr = malloc(s->len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "malloc() failed\n");
    exit(EXIT_FAILURE);
  }
  s->ptr[0] = '\0';
}

///
///function receive data from server
///
size_t write_function(void *ptr, size_t size, size_t nmemb, struct string *s){
	size_t new_len = s->len + size*nmemb;

	s->ptr = realloc(s->ptr, new_len+1);

	if (s->ptr == NULL) {
		fprintf(stderr, "realloc() failed\n");
		exit(EXIT_FAILURE);
	}
	memcpy(s->ptr+s->len, ptr, size*nmemb);
	s->ptr[new_len] = '\0';
	s->len = new_len;
	return size*nmemb;
}

///
///get block template 
///
json_t* getBlockTemplate(){
    CURL *curl = curl_easy_init();
    struct curl_slist *headers = NULL;
    struct string response;

    json_t *json_response;
	json_error_t json_error;
    init_string(&response);
    if (curl) {
		const char *data =
			"{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", \"method\": \"getblocktemplate\", \"params\": [] }";
	
		headers = curl_slist_append(headers, "content-type: text/plain;");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	
		curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.50.1:8332/");
	
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(data));
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
		curl_easy_setopt(curl, CURLOPT_USERPWD,"dinhhongphi:x");
	
		curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);
		curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,write_function);
		curl_easy_setopt(curl,CURLOPT_WRITEDATA,&response);
		curl_easy_perform(curl);

        //convert result to json object
		json_response = json_loads(response.ptr,0,&json_error);
        if(json_response){
            return json_response;
        }
        return NULL;
    }
    return NULL;
}

bool my_sha256(void *digest, const void *buffer, size_t length) {
	gcry_md_hash_buffer(GCRY_MD_SHA256, digest, buffer, length);
	return true;
}


int main(int argc, char* argv[])
{
    //init MPI
    int rank, size;
    MPI_Init (&argc, &argv);      /* starts MPI */
    MPI_Comm_rank (MPI_COMM_WORLD, &rank);        /* get current process id */
    MPI_Comm_size (MPI_COMM_WORLD, &size);        /* get number of processes */
    char processor_name[MPI_MAX_PROCESSOR_NAME];
    int name_len;
    MPI_Get_processor_name(processor_name, &name_len); 
    printf("Process name %s have rank : %d\r\n",processor_name,rank);

    //define hash function
    b58_sha256_impl = my_sha256;
	blkmk_sha256_impl = my_sha256;

    int number;
    uint32_t nonce = 0;
    //master
    if(rank == 0){
        //json_t * result = getBlockTemplate(); 
        json_t * req;
        json_error_t jsone;
        const char *err;
        blktemplate_t *tmpl;
        //require slave find nonce
        int i = 1;
        int findSuccessStatus = 0;
        uint32_t nonceSusscess; //save nonce right
        
        tmpl = blktmpl_create();

        req = json_loads(blkmaker_test_input, 0, &jsone);
        
        err = blktmpl_add_jansson(tmpl, req, time(NULL));
        json_decref(req);

        if (err)
        {
            printf("Error adding block template: %s", err);
        }
        while (blkmk_time_left(tmpl, time(NULL)) && blkmk_work_left(tmpl))
	    {   
            
            unsigned char data[80];
            size_t datasz;
            unsigned int dataid;
            uint32_t nonce;
            datasz = blkmk_get_data(tmpl, data, sizeof(data), time(NULL), NULL, &dataid);            
            //return 0;
            uint32_t workStop = 0;
            while(i < size){ 
                //send hash range and data to slave
                MPI_Send(&workStop, 1, MPI_UNSIGNED, i, 0, MPI_COMM_WORLD);
                MPI_Send(&nonce, 1, MPI_UNSIGNED, i, 0, MPI_COMM_WORLD);
                uint32_t size_temp = sizeof(data);
                MPI_Send(&size_temp, 1, MPI_UNSIGNED, i, 0, MPI_COMM_WORLD);
                MPI_Send(&data, size_temp, MPI_CHAR, i, 0, MPI_COMM_WORLD);
                nonce += MAX_CACULATE;
                if(nonce >= 0x0000ffff){
                    printf("nonce largest\r\n");
                    break;
                }
                i++;
                if(i >= size){
                    int j = 1;
                    //receive data from slave
                    findSuccessStatus = 0;
                    while(j < size){
                        MPI_Recv(&findSuccessStatus, 1, MPI_UNSIGNED, j, 0, MPI_COMM_WORLD,MPI_STATUS_IGNORE);
                        if(findSuccessStatus == 1){
                            MPI_Recv(&nonceSusscess, 1, MPI_UNSIGNED, j, 0, MPI_COMM_WORLD,MPI_STATUS_IGNORE);
                            //stop all process
                            uint32_t k;
                            for(k = 1; k < size; k++){
                                workStop = 1;
                                MPI_Send(&workStop, 1, MPI_UNSIGNED, k, 0, MPI_COMM_WORLD);
                            }
                            break;
                        }
                        j++;
                    }
                    if(findSuccessStatus)
                        break;
                    //continue find nonce
                    i = 1;
                }
            }
        }
        printf("%s ended\r\n",processor_name);
    }else if(rank > 0){
        //slave, find nonce right
        unsigned char data[80], hash[32];
        uint32_t data_size = 0;
        blktemplate_t *tmpl;
        const char *err;
        json_t *json_blocktemplate;
        json_error_t json_error;
        int findSuccessStatus = 0;
        uint32_t workStop = 0;
        uint32_t i;
        while(1){
            //receive nonce and data from server to find right hash
            MPI_Recv(&workStop, 1, MPI_UNSIGNED, 0, 0, MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            if(workStop == 1) break;
            MPI_Recv(&nonce, 1, MPI_UNSIGNED, 0, 0, MPI_COMM_WORLD,MPI_STATUS_IGNORE);

            MPI_Recv(&data_size, 1, MPI_UNSIGNED, 0, 0, MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            MPI_Recv(&data, data_size, MPI_CHAR, 0, 0, MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            
            //find hash
            for(i = nonce; i < nonce + MAX_CACULATE; i++){
                *(uint32_t*)(&data[76]) = nonce;
                my_sha256(hash, data, 80);
                my_sha256(hash, hash, 32);
                
                if (!*(uint32_t*)(&hash[28])){
                    //find nonce success, send nonce to master
                    findSuccessStatus = 1;
                    MPI_Send(&findSuccessStatus, 1, MPI_UNSIGNED, 0, 0, MPI_COMM_WORLD);
                    MPI_Send(&nonce, 1, MPI_UNSIGNED, 0, 0, MPI_COMM_WORLD);
                    break;
                }
                    
            }
            printf("process %d on %s caculater hash from 0x%8x to 0x%8x\r\n",rank,processor_name,nonce,nonce+MAX_CACULATE);
            if(i >= MAX_CACULATE + nonce)
                MPI_Send(&findSuccessStatus, 1, MPI_UNSIGNED, 0, 0, MPI_COMM_WORLD);
        }
    }
    MPI_Finalize();
    return 0;
}
