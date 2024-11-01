#!/bin/bash
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
PURPLE='\033[1;35m'
NC='\033[0m'
while true; do
	read -p "Лог будет сохранён в текущей папке, согласны? y\\n
" dir
	if [[ $dir == "y" ]]; then
		mkdir -p "$(pwd)/cert_checker_logs"
		DIR="$(pwd)/cert_checker_logs"
		break
	elif [[ $dir == "n" ]]; then
		read -p "Введите полный путь до директории
" DIR
		cd "$DIR" 2>/dev/null || exit 1  
		break
	fi

done
mkdir -p "$DIR/cert_checker_logs"
DIR="$DIR/cert_checker_logs"



while true; do
	echo -e "${RED}Нужно авторизоваться!\n ${NC}"
	read -p $'\nЭто кластер K8S? y\\n\n\n' isKuber
	if [[ $isKuber == "y" ]]; then
		read -p $'\nВведи адрес API кластера\n\n' SERVER
		kubectl login $SERVER && break
	elif [[ $isKuber == "n" ]]; then
		read -p $'\nЗапроси токен в админ консоли в GUI и введи строку подключения далее (выглядит как "oc login --token...")\n' ocLogin
		$ocLogin && break
	fi
done		





NOW=$(date -d "$(date "+%Y-%m-%d %H:%M")"  "+%s")

echo -e "${YELLOW}Очистка директории $DIR${NC}"
rm -rf "${DIR}"/* 2>/dev/null
echo -e "${GREEN}Очистка завершена${NC}"





 while true; do
	 echo -e "${RED}Напиши название неймспейса${NC}
"	 
	 read -e  project
	 oc project $project
	 if [ $? -eq 0 ]; then
		break
	 fi
 done

 echo -e "
${GREEN}                      ---  Проверяется проект $project  ---${NC}
" | tee -a "${DIR}/cert_check_log.txt"

echo -e "${PURPLE}Введи все возможные пароли от кейсторов и трастсторов в твоём неймспейсе ЧЕРЕЗ ПРОБЕЛ.
По умолчанию будет использоваться самый первый.${NC}"
read -e -a secrets_pass_input_default
secret_pass=${secrets_pass_input_default[0]}

#функция для вычисления оставшихся дней из полученных через keytool сроков действия	
timestamp_calc() {
	local input_date="$1"
	local timestamp=$(date -d "$input_date" "+%s")
#Переводим разницу в секундах в дни
	local days_left=$((("$timestamp-$NOW")/86400))
	cnLen=${#CN}
	spaceCount=$(echo $((40 - $cnLen)))
	if [ "$days_left" -gt 40 ]; then
		echo -en "${GREEN} "$CN"" && perl -e "print ' ' x $spaceCount" && echo -e "Осталось $days_left дней ${NC}" | tee -a "${DIR}/cert_check_log.txt"	
	elif [ "$days_left" -lt 40 ] && [ "$days_left" -gt 14 ]; then
		echo -en "${YELLOW} "$CN"" && perl -e "print ' ' x $spaceCount" && echo -e "Осталось $days_left дней ${NC}" | tee -a "${DIR}/cert_check_log.txt"	
	elif [ "$days_left" -lt 14 ] && [[ "$input_date" != '' ]]; then
		echo -en  "${RED} "$CN""$spacebars"" && perl -e "print ' ' x $spaceCount" && echo -e "---ВНИМАНИЕ!!!  Осталось $days_left дней   ВНИМАНИЕ!!!---${NC}" | tee -a "${DIR}/cert_check_log.txt"	
	else
		echo -e "${RED}Файл: $secret_file пропущен, проверьте его вручную! ${CN}" | tee -a "${DIR}/cert_check_log.txt" | tee -a "${DIR}/cert_check_log.txt"
	fi	
	
	
}












#функция проверки типа кейстора
type_checker() {
	oc get secret $secret -o json | jq  '.data."'"$secret_file"'"' |  base64 -di > "${DIR}/${secret}/${secret_file}"
	cd ${DIR}/${secret}
	type_index="-storetype PKCS12"
	keytool -list -v -keystore $secret_file $type_index -storepass "$secret_pass" > /dev/null 2>&1 
	type_trigger=$(echo $?)
	type_list=( "-storetype PFX" "-storetype PKCS11" "-storetype JKS" "-storetype pkcs12"  "")
	if [ $type_trigger -eq 1 ]; then
		for type_index in "${type_list[@]}"; do
			keytool -list -v -keystore $secret_file $type_index -storepass "$secret_pass" > /dev/null 2>&1 
			type_trigger=$(echo $?)
			if [ $type_trigger -eq 0 ]; then
				break	
			fi
		done
	fi
}




#функция проверки кейсторов
keystore_checker() {
	echo -e "${PURPLE} Проверяется keystore: $secret_file в $secret ${NC}" | tee -a "${DIR}/cert_check_log.txt"
	secret_pass=($secrets_pass_input_default)
	index=0
	type_checker
	keytool -list -v -keystore $secret_file $type_index -storepass "$secret_pass" > /dev/null 2>&1 
	trigger=$(echo $?)
	if [ $trigger -eq 1 ]; then
		for secret_pass in  "${secrets_pass_input_default[@]}"; do
			keytool -list -v -keystore $secret_file $type_index -storepass "$secret_pass" > /dev/null 2>&1 
			trigger=$(echo $?)
			if [ $trigger -eq 0 ]; then
				break
			fi
		done
	fi
	while [ $trigger  -eq 1 ]; do		
		  	echo -e "${RED}Пароль не подошёл, введи пароль от $secret_file в $secret  ${NC}" | tee -a "${DIR}/cert_check_log.txt"
		  	read -e -r secrets_pass_input_manual
		  	secret_pass=($secrets_pass_input_manual) 
			type_checker
			if [[ $secrets_pass_input_manual  == 'skip'   ||   $secrets_pass_input_manual  == "s" ]]; then
				break
			else			
				
				secrets_pass_input_default+=("$secrets_pass_input_manual")
#вызов функции проверки на тип
				type_checker
		  		keytool -list -v -keystore $secret_file $type_index -storepass "$secret_pass" > /dev/null 2>&1
				trigger=$(echo $?)	
			
			fi
	done
	if [[ $secret_pass != 'skip' &&  $secret_pass != "s" ]]; then
		echo "Подошёл пароль: $secret_pass"
	fi
		

#Перебираем все valid даты кейстора

	
	keystore_untill_time=`keytool -list -v -keystore $secret_file $type_index -storepass "$secret_pass" 2>/dev/null | grep until: | sed 's/.*until: //' | perl -p -e 'chomp if eof'` > /dev/null 2>&1
	readarray -t keystore_untill_time_array <<< "$keystore_untill_time"			

#Если список дат  выше пустой, значит мы пропустили кейстор, либо он битый, покажем цепочку только, если список не пуст 
	if [[ "$keystore_untill_time" == '' ]]; then
		echo '===============================' | tee -a "${DIR}/cert_check_log.txt"
	else	
		echo -e "${YELLOW}ЦЕПОЧКИ КЕЙСТОРА: $secret_file${NC}" | tee -a "${DIR}/cert_check_log.txt"
		keytool -list -v -keystore $secret_file  $type_index -storepass "$secret_pass" 2>/dev/null | grep -E  "Alias|Owner" | sed 's/Owner: //' | sed 's/, O=.*//' | sed 's/, OU=.*//' | sed 's/EMAIL.*,//' | sed 's/CN=//' |  tee -a "${DIR}/cert_check_log.txt"
	fi
#Перебираем все CN кейстора

	cn_list_stores=`keytool -list -v -keystore $secret_file $type_index -storepass "$secret_pass" 2>/dev/null | grep -B 4 until: | grep Owner | sed 's/.*CN=//' | sed 's/,.*//' | perl -p -e 'chomp if eof'` > /dev/null 2>&1				
	readarray -t cn_array_stores <<< "$cn_list_stores"						

	for store in "${keystore_untill_time_array[@]}"; do
			
		#alias=${alias_array[$index]}
		CN=${cn_array_stores[$index]}		
		timestamp_calc "$store"	
		index=$((index + 1))
	done
	
}


secrets_list=$(oc get secrets | grep Opaque | awk '{print $1}') 

secret_array=($secrets_list)


#echo `oc get secret "${secret_array[0]}" -o json | jq  .data | jq 'with_entries(select(.key | test("crt$|p12$|pfx$|jks$|pem$|cer$")))' | jq keys | jq -r .[]` >> "${DIR}/test_output.txt"

echo -e "${GREEN}Collecting secret's files in ${DIR}${NC}" | tee  "${DIR}/cert_check_log.txt"	

#для каждого секрета смотрим имя каждого файла, если нужных нет, идём дальше
for secret in "${secret_array[@]}"; do
	secret=$secret | tr -d '\n' 

	file=`oc get secret $secret -o json | jq  .data | jq 'with_entries(select(.key | test("crt$|p12$|pfx$|jks$|pem$|cer$")))' | jq keys | jq -r .[] | tr -d ' ' | tr '\r' '\n'` 
	
	if [ -z "$file" ]; then
		echo -e "${YELLOW}В сикрете $secret отсутствуют сертификаты и кейсторы${NC}" | tee -a "${DIR}/cert_check_log.txt"
		
#создаём папку секрета, если в секрете есть кейсторы или серты. В неё будем класть файлы секрета
	else
		mkdir -p "${DIR}/${secret}"
		secret_files_array=($file)
#если есть серты, то их декодируем и кидаем в папку с названием сикрета, оттуда будем читать кейтулом
		for secret_file in "${secret_files_array[@]}"; do 
#если видим key.pem, то благополучно игнорим, там сертов нет.
			if [[ "$secret_file" =~ (^.*key\.pem)$ ]]; then
				echo -e "${YELLOW}В  $secret_file содержится ключ, продолжаю проверку ${NC} "
			elif [[ "$secret_file" =~ (crt|pem|cer)$ ]]; then
				index=0
				echo -e "${PURPLE} Проверяются сертификаты из файла $secret_file в $secret ${NC}" | tee -a "${DIR}/cert_check_log.txt"	
				oc get secret $secret -o json | jq  '.data."'"$secret_file"'"' |  base64 -di | sed  's/-----END CERTIFICATE----- /-----END CERTIFICATE-----/' > "${DIR}/${secret}/${secret_file}"
				certs_untill_time=`keytool -printcert -v -file "${DIR}/${secret}/${secret_file}" 2>/dev/null | grep until: | sed 's/.*until: //' | perl -p -e 'chomp if eof'` > /dev/null 2>&1
#записываем сроки действия всех сертов в файле в массив, затем каждый должен будет обрабатываться функцией timestamp_calc
			    readarray -t certs_untill_time_array <<< "$certs_untill_time"	
			    cn_list_certs=`keytool -printcert -v -file "${DIR}/${secret}/${secret_file}"  | grep -B 4 until: | grep Owner | sed 's/.*CN=//' | sed 's/,.*//' | perl -p -e 'chomp if eof'` > /dev/null 2>&1	
			    readarray -t cn_array_certs <<< "$cn_list_certs"			
			    for cert in "${certs_untill_time_array[@]}"; do 
				#ВЫЗОВ ФУНКЦИИ  ТУТ		             
				                      CN=${cn_array_certs[$index]}
						      alias=""
		             timestamp_calc "$cert"
			        index=$((index + 1))
			    done	
				
							
			else 
			    keystore_checker	
			fi
	    done	
	fi

done


 echo -e "


                ${GREEN} ---- ПРОВЕРКА ЗАВЕРШЕНА! ----   ${NC}



 "





