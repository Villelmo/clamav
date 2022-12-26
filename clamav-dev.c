/*
 * clamav-devc.c
 *
 * (c) Author: David Quiroga
 * e-mail: david (at) clibre (dot) io
 *
 ***************************************************************
 * Descripción:
 *
 * Uso de la libreria libclamav para buscar malware en ficheros
 *
 * SPDX-License-Identifier: GPL-3.0
 *
 * gcc -Wall clamav-devc.c -o clamav-devc `pkg-config libclamav --cflags --libs`
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <clamav.h>
#include <errno.h>
#include <dirent.h>
#include <locale.h>

#define MAX_BUF 200
typedef struct clamav_eng_s {
    struct cl_engine *engine;
    struct cl_scan_options options;
    unsigned long int tot_size;
    unsigned int tot_files;
    unsigned int tot_infected_files;
    unsigned int tot_fileserr;
    unsigned int sigs;
    int ret;
    char resbuff[MAX_BUF];
} clamav_eng_s;

enum { AVOK, AVINFECTED, AVERROR, AVFILENF };

/*
 * Exit codes:
 * AVOK: no se detecto virus
 * AVINFECTED: infectado
 * AVERROR: error en el motor
 * AVFILENF: error al abrir el fichero
 */

#define VERDE "\033[1;32m"
#define ROJO "\033[0;31m"
#define NEUTRO "\033[0m"

// create a new motor, load firm list and add the options that during the scanning and then with scan_file pass the directory 
int load_engine_av(clamav_eng_s *clamav_eng)
{
    clamav_eng->tot_size = 0;
    clamav_eng->sigs = 0;
    clamav_eng->tot_files = 0;
    clamav_eng->tot_fileserr = 0;
    clamav_eng->tot_infected_files = 0;

    if ((clamav_eng->ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) {
        snprintf(clamav_eng->resbuff, MAX_BUF,
                "No se puede inicializar libclamav: %s",
                cl_strerror(clamav_eng->ret));
        return AVERROR;
    }

    if (!(clamav_eng->engine = cl_engine_new())) {
        snprintf(clamav_eng->resbuff, MAX_BUF,
                "No se puede crear un nuevo motor");
        return AVERROR;
    }

    // carga la db
    if ((clamav_eng->ret = cl_load(cl_retdbdir(), clamav_eng->engine,
                            &clamav_eng->sigs, CL_DB_STDOPT)) != CL_SUCCESS) {
        snprintf(clamav_eng->resbuff, MAX_BUF,
                "Error en cl_load: %s", cl_strerror(clamav_eng->ret));
        cl_engine_free(clamav_eng->engine);
        return AVERROR;
    }

    // construye el motor
    if ((clamav_eng->ret = cl_engine_compile(clamav_eng->engine)) != CL_SUCCESS) {
        snprintf(clamav_eng->resbuff, MAX_BUF,
            "Error al inicializar la DB: %s", cl_strerror(clamav_eng->ret));
        cl_engine_free(clamav_eng->engine);
        return AVERROR;
    }

    // añadimos las opciones
    memset(&clamav_eng->options, 0, sizeof(struct cl_scan_options));
    clamav_eng->options.parse |= ~0;
    clamav_eng->options.general |= CL_SCAN_GENERAL_HEURISTICS;

    snprintf(clamav_eng->resbuff, MAX_BUF,
            "Clamav iniciado: Cargadas %u firmas", clamav_eng->sigs);
    return AVOK;
}

int scan_file (clamav_eng_s *clamav_eng, char *filename)
{
    int fd=0;
    const char *virname;
    errno=0;

    if ((fd = open(filename, O_RDONLY)) == -1) {
        clamav_eng->tot_fileserr++;
        snprintf(clamav_eng->resbuff, MAX_BUF,
                "%s - %s%s%s", filename, ROJO, strerror(errno), NEUTRO);
        return AVFILENF;
    }

    clamav_eng->ret = cl_scandesc(fd, filename, &virname, &clamav_eng->tot_size,
                                    clamav_eng->engine, &clamav_eng->options);
    close(fd);
    clamav_eng->tot_files++;

    if (clamav_eng->ret == CL_VIRUS) {
        clamav_eng->tot_infected_files++;
        snprintf(clamav_eng->resbuff, MAX_BUF, "Virus detectado: %s", virname);
        return AVINFECTED;
    } else {
        if (clamav_eng->ret == CL_CLEAN) {
         snprintf(clamav_eng->resbuff, MAX_BUF, "%s✔%s", VERDE, NEUTRO);
         return AVOK;
        } else {
         snprintf(clamav_eng->resbuff, MAX_BUF, "Error: %s",
                    cl_strerror(clamav_eng->ret));
         return AVERROR;
        }
    }
}

void clouse_engine_av(clamav_eng_s *clamav_eng)
{
    // liberar memoria
    cl_engine_free(clamav_eng->engine);
}

long double sizescan_engine_av(unsigned long int tot_size)
{
    long double mb = 0;
    mb = tot_size * (CL_COUNT_PRECISION / 1024) / 1024.0;
    return mb;
}

void print_resume (clamav_eng_s clamav_eng)
{
    printf("\n------\n");
    printf("Cargadas %u firmas\n", clamav_eng.sigs);
    printf("Ficheros escaneados: %d\n", clamav_eng.tot_files);
    printf("Ficheros no accesibles: %d\n", clamav_eng.tot_fileserr);
    printf("Ficheros infectados: %d\n", clamav_eng.tot_infected_files);
    printf("Total datos escaneados: %2.2Lf MB\n",
            sizescan_engine_av(clamav_eng.tot_size));
}

// create the structure that contain the data of connection 
// and results of each operation that make in the motor 
int main(void)
{
    DIR *dirp;
    struct dirent *dp;
    clamav_eng_s clamav_eng = {};

    setlocale(LC_ALL, "");

    printf("Iniciando motor clamav...\n");
    // Inicializamos el motor antivirus y cargamos las firmas
    if (load_engine_av(&clamav_eng) != AVOK) {
     printf("load_engine_av: %s\n", clamav_eng.resbuff);
     exit(AVERROR);
    }
    printf("%s\n", clamav_eng.resbuff);
    // Analizamos todos los ficheros del directorio
    dirp = opendir (".");
    if (dirp == NULL) {
     printf("No se puede acceder a los ficheros del direcctorio\n");
     exit(EXIT_FAILURE);
    }
    printf("Escaneando ficheros:\n\n");
    do {
        errno=0;
        dp = readdir(dirp);
        if (dp == NULL)
         break;
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
        continue;
        if (dp->d_type == DT_REG) {
        switch (scan_file (&clamav_eng, dp->d_name))
            {
            case AVINFECTED:// virus encontrado
            printf("%s", ROJO);
            case AVOK: // fichero no infectado
            printf("%s - %s%s\n", dp->d_name, clamav_eng.resbuff, NEUTRO);
            break;
            case AVFILENF: // error al abril el fichero
            printf("%s\n", clamav_eng.resbuff);
            break;
            default: // cualquier otro valor
            printf("scan_file: %s\n", clamav_eng.resbuff);
            clouse_engine_av (&clamav_eng);
            exit(AVERROR);
            }
        }
    } while (!0);

    if (errno != 0) {
     printf("Se han encontrado errores al leer los fichero: %s\n",
            strerror(errno));
     exit(EXIT_FAILURE);
    }
    if (closedir(dirp) == -1) {
     printf("Error en closedir\n");
     exit(EXIT_FAILURE);
    }

    // Imprimimos el resumen de resultados
    print_resume (clamav_eng);

    // Cerramos el motor y liberamos
    clouse_engine_av (&clamav_eng);

    return EXIT_SUCCESS;
}
