#include <iostream>
#include <map>
#include <vector>
#include <fstream>
#include <fcntl.h>
#include <iomanip>
#include <sstream>
#include <string>
#include <stdio.h>
#include <cryptlib.h>
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include "base64.h"
 
using namespace CryptoPP;
 
// AES EBC encryption (output Base64)
std::string aes_encrypt_ecb_base64(std::string data , unsigned char* key, int keylen)
{
    std::string encrypt_str;
    try 
    {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption ecb_encription(key, keylen);
        CryptoPP::StreamTransformationFilter stf_encription(
            ecb_encription,
            new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encrypt_str)),
            CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING
        );
        stf_encription.Put(reinterpret_cast<const unsigned char*>(data.c_str()), data.length() + 1);
        stf_encription.MessageEnd();
    }
    catch (std::exception e) {
        std::cout << e.what() << std::endl;
    }
 
    return encrypt_str;
}
 
 // AES EBC encryption (output HEX) 
std::string aes_encrypt_ecb_hex(std::string data , unsigned char* key, int keylen)
{
    std::string encrypt_str;
 
    try 
    {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption ecb_encription(key, keylen);
        CryptoPP::StreamTransformationFilter stf_encription(
            ecb_encription,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(encrypt_str)),
            CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING
        );
        stf_encription.Put(reinterpret_cast<const unsigned char*>(data.c_str()), data.length() + 1);
        stf_encription.MessageEnd();
    }
    catch (std::exception e) {
        std::cout << e.what() << std::endl;
    }
 
    return encrypt_str;
}
 
 // AES EBC decryption (output Base64)
std::string aes_decrypt_ecb_base64(std::string base64_data, unsigned char* key, int keylen)
{
    try 
    {
        std::string aes_encrypt_data;
        CryptoPP::Base64Decoder decoder;
        decoder.Attach(new CryptoPP::StringSink(aes_encrypt_data));
        decoder.Put(reinterpret_cast<const unsigned char*>(base64_data.c_str()), base64_data.length());
        decoder.MessageEnd();
 
        std::string decrypt_data;
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption ebc_description(key, keylen);
        CryptoPP::StreamTransformationFilter stf_description(
            ebc_description,
            new CryptoPP::StringSink(decrypt_data), 
            CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING
        );
 
        stf_description.Put(
            reinterpret_cast<const unsigned char*>(aes_encrypt_data.c_str()), 
            aes_encrypt_data.length()
        );
        stf_description.MessageEnd();
 
        return decrypt_data;
    }
    catch (std::exception e) {
        std::cout << e.what() << std::endl;
        return "";
    }
}
 
 // AES EBC Decryption (Output HEX)
std::string aes_decrypt_ecb_hex(std::string hex_data, unsigned char* key, int keylen)
{
    try
    {
        std::string aes_encrypt_data;
        CryptoPP::HexDecoder decoder;
        decoder.Attach(new CryptoPP::StringSink(aes_encrypt_data));
        decoder.Put(reinterpret_cast<const unsigned char*>(hex_data.c_str()), hex_data.length());
        decoder.MessageEnd();
 
        std::string decrypt_data;
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption ebc_description(key, keylen);
        CryptoPP::StreamTransformationFilter stf_description(
            ebc_description,
            new CryptoPP::StringSink(decrypt_data),
            CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING
        );
 
        stf_description.Put(
            reinterpret_cast<const unsigned char*>(aes_encrypt_data.c_str()),
            aes_encrypt_data.length()
        );
        stf_description.MessageEnd();
 
        return decrypt_data;
    }
    catch (std::exception e) {
        std::cout << e.what() << std::endl;
        return "";
    }
}

const int SIZE = 16;

std::string generator_pass()
{
	std::srand(std::time(nullptr));
	std::string str = "";// создаем пустую строчку
	for (int i = 0; i < SIZE; i++)
	{
		if (i % 2 == 0)
		{
			if (i % 4 == 0)
			{
				//буквы в нижнем регистре
				str.push_back(char('a' + rand() % 26));
			}
			else
			{
				str.push_back(char('0' + rand() % 10));
			}
		}
		else
		{
			if (i % 3 == 0)
			{
				//#,&,* и т.д
				str.push_back(char('!' + rand() % 14));
			}
			else
			{
				str.push_back(char('A' + rand() % 26)); // буквы в верхнем регистре
			}
		}
	}
	return str;
}

std::vector <std::string> Parse(std::string str_in) 
{
	std::string str_out = "";
	std::vector<std::string> vec;
	for (int i = 0; i < str_in.size(); i++)
	{
		if (str_in[i] != ' ') // собираем строчку пока не встретили " "
		{
			str_out.push_back(str_in[i]);
		}
		else // как только встретили " "
		{
			vec.push_back(str_out);
			str_out = "";
		}
	}
	vec.push_back(str_out);
	vec.shrink_to_fit();
	return vec;
}

int check_pass(std::string &password)
{
	int i = 0;
	int count_symb = 0;
	int count_low_reg = 0;
	int count_up_reg = 0;
	while(i != password.size()) // проверка на криптоустойчивость
	{
		for(int j = 33;j < 48; j++)
		{
			if(password[i] == char(j)) //если находим хотя-бы 1 из этих символов
			{
				count_symb++;
			}
		}
		for (int k = 97; k < 123; k++) // и из этих
		{
			if(password[i] == char(k))
			{
				count_low_reg++;
			}
		}
		for (int p = 65; p < 91; p++) // и из этих
		{
			if (password[i] == char(p))
			{
				count_up_reg++;
			}
		}
		i++;
	}
	if(count_low_reg > 0 && count_symb > 0 && count_up_reg > 0)
	{
		return 1;
	}
	return 0;
}

class base
{
private:
	std::string login;
	std::string password;
	std::string servis;
public:
	void getdata(std::map<std::string , std::pair<std::string,std::string>>& mapa)
	{
		std::string ch;
		std::string pass;
		std::cout << "Введите предпочитаемый сервис: ";
		getline(std::cin,servis);
		std::cout << "Введите логин: ";
		getline(std::cin,login);
		std::cout << "Сгенерировать пароль или произвести ввод самостоятельно?(1/0): ";
		getline(std::cin,ch);
		if(ch == "1")
		{
			pass = generator_pass();
			mapa[servis] = std::make_pair(login,pass);
			std::cout << "Пользователь добавлен!"<< std::endl;
		}
		else if(ch == "0")
		{
			std::cout << "Введите пароль: ";
			getline(std::cin,password);
			if(check_pass(password) == 1)
			{
				mapa[servis] = std::make_pair(login,password);
				std::cout << "Пользователь добавлен!"<< std::endl;
			}
			else
			{
				std::cout << "Пароль слабый, используйте больше специальных символов или прописных букв! "<< std::endl;
				std::cout << "Рекомендуется сгенерировать пароль или ввести его еще раз" << std::endl;
				std::cout << "Использовать этот пароль или сгенерировать более защищенный?(1/0): ";
				getline(std::cin,ch);
				if(ch == "1") // при этой команде срабатывает else в мейне
				{
					mapa[servis] = std::make_pair(login,password);
					std::cout << "Пользователь добавлен!" << std::endl;
					return;
				}
				else if(ch == "0")
				{
					pass = generator_pass();
					mapa[servis] = std::make_pair(login,pass);
					std::cout << "Пользователь добавлен!" << std::endl;
					return;
				}
			}
		}
		else
		{
			std::cout << "Неверный выбор!" << std::endl;
		}
	}
	void showdata(std::map < std::string, std::pair< std::string,std::string > > &mapa, std::string serv)
	{
		for (auto iter : mapa)
		{
			if(serv == "All" || serv == "all")
			{
				std::cout << "Пароль: " << iter.second.second << std::endl;
			}
			else if(serv != "All" || serv != "all")
			{
				if(serv == iter.first)
				{
					std::cout << "Пароль: " <<  iter.second.second << std::endl;
				}
			}
		}
	}
	void showcom()
	{
		int count = 0;
		std::cout << ++count << ")" << "NewData - создаются новые данные" << std::endl;
		std::cout << ++count << ")" << "Showdata all/servis - показывает все или какие-то конкретные данные" << std::endl;
		std::cout << ++count << ")" << "Help - показывает все команды" << std::endl;
		std::cout << ++count << ")" << "Exit - выходит из программы" << std::endl;
		std::cout << ++count << ")" << "Delete servis - Удаляет данные из хранилища с использованием ввода логина" << std::endl;
		std::cout << ++count << ")" << "ChPass servis - изменяет пароль используя верный логин" << std::endl;
		std::cout << ++count << ")" << "Find servis - находит сервис по его имени" << std::endl;
	}
	std::string show_servises(std::map<std::string,std::pair<std::string,std::string>> &mapa, std::string name_servis)
	{
		if(name_servis == "") // все сервисы
		{
			std::cout << "Все сервисы: " << std::endl;
			for(auto iter: mapa)
			{
				std::cout << iter.first <<std::endl;
			}
		}
		else // конкретный сервис
		{
			for(auto iter: mapa)
			{
				if(name_servis == iter.first)
				{
					return "Данные для этого сервиса уже есть!";//"Data for this servis already have! ";
				}
			}
		}
		return "Данные для этого сервиса не найдены! ";
	}
};

int main(int argc,char* argv[]) 
{
	setlocale(LC_ALL,"ru");
	std::cout << "Добро пожаловать!" << std::endl;
	std::map<std::string, std::pair<std::string, std::string>> myMap;
	std::vector<std::string> vec_com;
	std::string key, value1,value2;
	base b1;
	std::ifstream fin("MyStorage.txt");
	while (fin >> key >> value1>> value2) // key - сервис, value1 - логин, value2 - пароль
	{
		std::string data_pass = aes_decrypt_ecb_hex(value2, (unsigned char*)"123456789ABCDEF", 16);// Дешифруем пароль
		std::string data_log = aes_decrypt_ecb_hex(value1, (unsigned char*)"123456789ABCDEF", 16);// Дешифруем логин
		std::string data_servis = aes_decrypt_ecb_hex(key, (unsigned char*)"123456789ABCDEF", 16);// Дешифруем сервис
		myMap[data_servis] = std::make_pair(data_log,data_pass);
	}
	std::ofstream fout("MyStorage.txt");
	while(true)
	{
		try
		{
			std::string command = "";
			std::cout << "Введите команду: ";
			std::getline(std::cin, command);
			std::cin.clear();
			vec_com = Parse(command); //распарсили строку команды
			if (vec_com[0] == "NewData")
			{
				b1.getdata(myMap);
			}
			else if (vec_com[0] == "ShowData") 
			{
				if (vec_com[1] == "All")
				{
					b1.showdata(myMap,vec_com[1]);
				}
				else if (vec_com[1] != "All" ) 
				{
					b1.showdata(myMap, vec_com[1]);
				}
			}
			else if (vec_com[0] == "Help")
			{
				b1.showcom();
			}
			else if (vec_com[0] == "Exit")
			{
				break;
			}
			else if (vec_com[0] == "Delete")
			{
				myMap.erase(vec_com[1]);
				std::cout << "Пользователь удален!" << std::endl;
			}
			else if (vec_com[0] == "ChPass") // сделать ChPass servis
			{
				std::string newPass,login;
				std::cout << "Введите логин: ";
				getline(std::cin, login);
				std::cout << "Введите новый пароль: ";
				getline(std::cin,newPass);
				if(check_pass(newPass) == 1)
				{// добавить проверку на криптоустойчивость
					myMap[vec_com[1]] = std::make_pair(login,newPass);
					std::cout << "Пароль изменен!" << std::endl;
				}
				else
				{
					std::cout << "Пароль не валидный. Используется автогенерация для лучшей защиты данных: " << std::endl;
					myMap[vec_com[1]] == std::make_pair(login,generator_pass());
				}
			}
			else if(vec_com[0] == "Find")
			{
				std::string str;
				if(vec_com.size() == 1)
				{
					str = b1.show_servises(myMap, "");
					std::cout << str << std::endl;
				}
				else
				{
					str = b1.show_servises(myMap,vec_com[1]);
					std::cout << str << std ::endl;
				}
			}
			}
		catch (const std::exception& ex)
		{
			std::cout << ex.what() << std::endl;
			std::cout << "Сохранение данных: " << std::endl;
		}
	};
	for (auto iter : myMap)
	{
		//записываем все как обычно (сервис + логин + шифр значение пароля)
		std::string shiphr_pass = aes_encrypt_ecb_hex(iter.second.second, (unsigned char*)"123456789ABCDEF", 16);
		std::string shiphr_log = aes_encrypt_ecb_hex(iter.second.first, (unsigned char*)"123456789ABCDEF", 16);
		std::string shiphr_serv = aes_encrypt_ecb_hex(iter.first, (unsigned char*)"123456789ABCDEF", 16);
		fout << shiphr_serv << "\t" << shiphr_log << "\t" << shiphr_pass <<"\n";
	}
	//Добавить код на проверку нажатия клавиши crtl+c в консоли
	fout.close();
	fin.close();
	return 0;
}