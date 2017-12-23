// 
// Author: Rich Kelley
// Email: rk5devmail@gmail.com
// License: MIT
// 

#include <Python.h>
#include <assert.h>
#include <pthread.h>

#include "structmember.h"
#include "common.h"
#include "types.h"
#include "memory.h"
#include "status.h"
#include "user_options.h"
#include "hashcat.h"

#ifndef MAXH
#define MAXH 100
#endif

static PyObject *ErrorObject;

PyDoc_STRVAR(rules__doc__,
"rules\tlist\tList of rules files to use\n\n");

PyDoc_STRVAR(event_types__doc__,
"event_types\ttuple\tReference list of event signals to use for callbacks\n\n\
DETAILS:\n\
Signals are used to bind callbacks to hashcat events.\n\
Ex: hc.event_connect(callback=cracked_callback, signal=\"EVENT_CRACKER_HASH_CRACKED\")\n\n");

/* hashcat object */
typedef struct
{

  PyObject_HEAD hashcat_ctx_t * hashcat_ctx;
  user_options_t *user_options;
  hashcat_status_t *hashcat_status;
  int rc_init;

  PyObject *hash;
  PyObject *mask;
  PyObject *dict1;
  PyObject *dict2;
  PyObject *rp_files;
  PyObject *event_types;
  int hc_argc;
  char *hc_argv[];

} hashcatObject;

typedef struct event_handlers_t
{
  
  int id;
  hashcatObject *hc_self;
  PyObject *callback;
  char *esignal;

} event_handlers_t;

const char *event_strs[] = {
  
"EVENT_AUTOTUNE_FINISHED",
"EVENT_AUTOTUNE_STARTING",
"EVENT_BITMAP_INIT_POST",
"EVENT_BITMAP_INIT_PRE",
"EVENT_CALCULATED_WORDS_BASE",
"EVENT_CRACKER_FINISHED",
"EVENT_CRACKER_HASH_CRACKED",
"EVENT_CRACKER_STARTING",
"EVENT_HASHLIST_COUNT_LINES_POST",
"EVENT_HASHLIST_COUNT_LINES_PRE",
"EVENT_HASHLIST_PARSE_HASH",
"EVENT_HASHLIST_SORT_HASH_POST",
"EVENT_HASHLIST_SORT_HASH_PRE",
"EVENT_HASHLIST_SORT_SALT_POST",
"EVENT_HASHLIST_SORT_SALT_PRE",
"EVENT_HASHLIST_UNIQUE_HASH_POST",
"EVENT_HASHLIST_UNIQUE_HASH_PRE",
"EVENT_INNERLOOP1_FINISHED",
"EVENT_INNERLOOP1_STARTING",
"EVENT_INNERLOOP2_FINISHED",
"EVENT_INNERLOOP2_STARTING",
"EVENT_LOG_ERROR",
"EVENT_LOG_INFO",
"EVENT_LOG_WARNING",
"EVENT_LOG_ADVICE",
"EVENT_MONITOR_RUNTIME_LIMIT",
"EVENT_MONITOR_STATUS_REFRESH",
"EVENT_MONITOR_TEMP_ABORT",
"EVENT_MONITOR_THROTTLE1",
"EVENT_MONITOR_THROTTLE2",
"EVENT_MONITOR_THROTTLE3",
"EVENT_MONITOR_PERFORMANCE_HINT",
"EVENT_OPENCL_SESSION_POST",
"EVENT_OPENCL_SESSION_PRE",
"EVENT_OUTERLOOP_FINISHED",
"EVENT_OUTERLOOP_MAINSCREEN",
"EVENT_OUTERLOOP_STARTING",
"EVENT_POTFILE_ALL_CRACKED",
"EVENT_POTFILE_HASH_LEFT",
"EVENT_POTFILE_HASH_SHOW",
"EVENT_POTFILE_NUM_CRACKED",
"EVENT_POTFILE_REMOVE_PARSE_POST",
"EVENT_POTFILE_REMOVE_PARSE_PRE",
"EVENT_SELFTEST_FINISHED",
"EVENT_SELFTEST_STARTING",
"EVENT_SET_KERNEL_POWER_FINAL",
"EVENT_WORDLIST_CACHE_GENERATE",
"EVENT_WORDLIST_CACHE_HIT",  

};        

#define n_events_types (sizeof (event_strs) / sizeof (const char *))

const Py_ssize_t N_EVENTS_TYPES = n_events_types;
static event_handlers_t handlers[MAXH];
static int n_handlers = 0;
static int handler_id = 1000;
static PyTypeObject hashcat_Type;

#define hashcatObject_Check(v)      (Py_TYPE(v) == &hashcat_Type)

PyDoc_STRVAR(event_connect__doc__,
"event_connect(callback, signal)\n\n\
Register callback with dispatcher. Callback will trigger on signal specified\n\n");

static PyObject *hashcat_event_connect (hashcatObject * self, PyObject * args, PyObject *kwargs)
{

  // register the callbacks
  char *esignal = NULL;
  int _hid = NULL;
  PyObject *callback;
  static char *kwlist[] = {"callback", "signal", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "Os", kwlist, &callback, &esignal)) 
  {
    return NULL;
  }

  if (!PyCallable_Check(callback)) 
  {
     PyErr_SetString(PyExc_TypeError, "parameter must be callable");
     return NULL;
  }


  Py_XINCREF(callback);                              /* Add a reference to new callback */
  Py_XINCREF(self);
  _hid = ++handler_id;
  handlers[n_handlers].id = _hid;                    /* id for disconnect function (todo) */
  handlers[n_handlers].hc_self = self;
  handlers[n_handlers].callback = callback;          /* Remember new callback */
  handlers[n_handlers].esignal = esignal;
  n_handlers++;

  return Py_BuildValue ("i", _hid); 
  
}

static void event_dispatch(char *esignal, hashcat_ctx_t * hashcat_ctx, const void *buf, const size_t len)
{
    
    PyObject *result = NULL;
    PyObject *args;

    for(int ref = 0; ref < n_handlers; ref++)
    {
      if (handlers[ref].esignal != NULL)
      {
        if((strcmp(esignal, handlers[ref].esignal) == 0) || (strcmp("ANY", handlers[ref].esignal) == 0))
        {

          PyGILState_STATE state = PyGILState_Ensure();

            if(!PyCallable_Check(handlers[ref].callback))
            {
              fprintf(stderr, "event_dispatch: expected a callable\n");

            }
            else
            {

              args = Py_BuildValue("(O)", handlers[ref].hc_self);
              result = PyObject_Call(handlers[ref].callback, args, NULL);

              if(PyErr_Occurred())
              {
                PyErr_Print();

              }
            }

          Py_XDECREF(result);
          PyGILState_Release(state);
        }
      }
    }

}

static void event (const u32 id, hashcat_ctx_t * hashcat_ctx, const void *buf, const size_t len)
{

  char *esignal;
  int size = -1;

  switch (id)
  {
    case EVENT_AUTOTUNE_FINISHED:               size = asprintf(&esignal, "%s", "EVENT_AUTOTUNE_FINISHED"); break;
    case EVENT_AUTOTUNE_STARTING:               size = asprintf(&esignal, "%s", "EVENT_AUTOTUNE_STARTING"); break;
    case EVENT_BITMAP_INIT_POST:                size = asprintf(&esignal, "%s", "EVENT_BITMAP_INIT_POST"); break;
    case EVENT_BITMAP_INIT_PRE:                 size = asprintf(&esignal, "%s", "EVENT_BITMAP_INIT_PRE"); break;
    case EVENT_CALCULATED_WORDS_BASE:           size = asprintf(&esignal, "%s", "EVENT_CALCULATED_WORDS_BASE"); break;
    case EVENT_CRACKER_FINISHED:                size = asprintf(&esignal, "%s", "EVENT_CRACKER_FINISHED"); break;
    case EVENT_CRACKER_HASH_CRACKED:            size = asprintf(&esignal, "%s", "EVENT_CRACKER_HASH_CRACKED"); break;
    case EVENT_CRACKER_STARTING:                size = asprintf(&esignal, "%s", "EVENT_CRACKER_STARTING"); break;
    case EVENT_HASHLIST_COUNT_LINES_POST:       size = asprintf(&esignal, "%s", "EVENT_HASHLIST_COUNT_LINES_POST"); break;
    case EVENT_HASHLIST_COUNT_LINES_PRE:        size = asprintf(&esignal, "%s", "EVENT_HASHLIST_COUNT_LINES_PRE"); break;
    case EVENT_HASHLIST_PARSE_HASH:             size = asprintf(&esignal, "%s", "EVENT_HASHLIST_PARSE_HASH"); break;
    case EVENT_HASHLIST_SORT_HASH_POST:         size = asprintf(&esignal, "%s", "EVENT_HASHLIST_SORT_HASH_POST"); break;
    case EVENT_HASHLIST_SORT_HASH_PRE:          size = asprintf(&esignal, "%s", "EVENT_HASHLIST_SORT_HASH_PRE"); break;
    case EVENT_HASHLIST_SORT_SALT_POST:         size = asprintf(&esignal, "%s", "EVENT_HASHLIST_SORT_SALT_POST"); break;
    case EVENT_HASHLIST_SORT_SALT_PRE:          size = asprintf(&esignal, "%s", "EVENT_HASHLIST_SORT_SALT_PRE"); break;
    case EVENT_HASHLIST_UNIQUE_HASH_POST:       size = asprintf(&esignal, "%s", "EVENT_HASHLIST_UNIQUE_HASH_POST"); break;
    case EVENT_HASHLIST_UNIQUE_HASH_PRE:        size = asprintf(&esignal, "%s", "EVENT_HASHLIST_UNIQUE_HASH_PRE"); break;
    case EVENT_INNERLOOP1_FINISHED:             size = asprintf(&esignal, "%s", "EVENT_INNERLOOP1_FINISHED"); break;
    case EVENT_INNERLOOP1_STARTING:             size = asprintf(&esignal, "%s", "EVENT_INNERLOOP1_STARTING"); break;
    case EVENT_INNERLOOP2_FINISHED:             size = asprintf(&esignal, "%s", "EVENT_INNERLOOP2_FINISHED"); break;
    case EVENT_INNERLOOP2_STARTING:             size = asprintf(&esignal, "%s", "EVENT_INNERLOOP2_STARTING"); break;
    case EVENT_LOG_ERROR:                       size = asprintf(&esignal, "%s", "EVENT_LOG_ERROR"); break;
    case EVENT_LOG_INFO:                        size = asprintf(&esignal, "%s", "EVENT_LOG_INFO"); break;
    case EVENT_LOG_WARNING:                     size = asprintf(&esignal, "%s", "EVENT_LOG_WARNING"); break;
    case EVENT_LOG_ADVICE:                      size = asprintf(&esignal, "%s", "EVENT_LOG_ADVICE"); break;
    case EVENT_MONITOR_RUNTIME_LIMIT:           size = asprintf(&esignal, "%s", "EVENT_MONITOR_RUNTIME_LIMIT"); break;
    case EVENT_MONITOR_STATUS_REFRESH:          size = asprintf(&esignal, "%s", "EVENT_MONITOR_STATUS_REFRESH"); break;
    case EVENT_MONITOR_TEMP_ABORT:              size = asprintf(&esignal, "%s", "EVENT_MONITOR_TEMP_ABORT"); break;
    case EVENT_MONITOR_THROTTLE1:               size = asprintf(&esignal, "%s", "EVENT_MONITOR_THROTTLE1"); break;
    case EVENT_MONITOR_THROTTLE2:               size = asprintf(&esignal, "%s", "EVENT_MONITOR_THROTTLE2"); break;
    case EVENT_MONITOR_THROTTLE3:               size = asprintf(&esignal, "%s", "EVENT_MONITOR_THROTTLE3"); break;
    case EVENT_MONITOR_PERFORMANCE_HINT:        size = asprintf(&esignal, "%s", "EVENT_MONITOR_PERFORMANCE_HINT"); break;
    case EVENT_OPENCL_SESSION_POST:             size = asprintf(&esignal, "%s", "EVENT_OPENCL_SESSION_POST"); break;
    case EVENT_OPENCL_SESSION_PRE:              size = asprintf(&esignal, "%s", "EVENT_OPENCL_SESSION_PRE"); break;
    case EVENT_OUTERLOOP_FINISHED:              size = asprintf(&esignal, "%s", "EVENT_OUTERLOOP_FINISHED"); break;
    case EVENT_OUTERLOOP_MAINSCREEN:            size = asprintf(&esignal, "%s", "EVENT_OUTERLOOP_MAINSCREEN"); break;
    case EVENT_OUTERLOOP_STARTING:              size = asprintf(&esignal, "%s", "EVENT_OUTERLOOP_STARTING"); break;
    case EVENT_POTFILE_ALL_CRACKED:             size = asprintf(&esignal, "%s", "EVENT_POTFILE_ALL_CRACKED"); break;
    case EVENT_POTFILE_HASH_LEFT:               size = asprintf(&esignal, "%s", "EVENT_POTFILE_HASH_LEFT"); break;
    case EVENT_POTFILE_HASH_SHOW:               size = asprintf(&esignal, "%s", "EVENT_POTFILE_HASH_SHOW"); break;
    case EVENT_POTFILE_NUM_CRACKED:             size = asprintf(&esignal, "%s", "EVENT_POTFILE_NUM_CRACKED"); break;
    case EVENT_POTFILE_REMOVE_PARSE_POST:       size = asprintf(&esignal, "%s", "EVENT_POTFILE_REMOVE_PARSE_POST"); break;
    case EVENT_POTFILE_REMOVE_PARSE_PRE:        size = asprintf(&esignal, "%s", "EVENT_POTFILE_REMOVE_PARSE_PRE"); break;
    case EVENT_SELFTEST_FINISHED:               size = asprintf(&esignal, "%s", "EVENT_SELFTEST_FINISHED"); break;
    case EVENT_SELFTEST_STARTING:               size = asprintf(&esignal, "%s", "EVENT_SELFTEST_STARTING"); break;
    case EVENT_SET_KERNEL_POWER_FINAL:          size = asprintf(&esignal, "%s", "EVENT_SET_KERNEL_POWER_FINAL"); break;
    case EVENT_WORDLIST_CACHE_GENERATE:         size = asprintf(&esignal, "%s", "EVENT_WORDLIST_CACHE_GENERATE"); break;
    case EVENT_WORDLIST_CACHE_HIT:              size = asprintf(&esignal, "%s", "EVENT_WORDLIST_CACHE_HIT"); break;

  }

  // Signal unassigned do nothing
  if (size == -1)
    return;

  event_dispatch(esignal, hashcat_ctx, buf, len);
  free(esignal);
}

PyDoc_STRVAR(reset__doc__,
"hashcat_reset\n\n\
Completely reset hashcat session to defaults.\n\n");

/*
  NOTE: A reset function may not be needed. It may be better to delete the hashcat object and reinstantiate a new one.
        However, deleting the hashcat object does not ensure that dealloc is called because it's up to the interpreter
        to schedule garbage collection. This may cause memory problems if new objects are created but the memory isn't
        deallocated even when ref counts are zero. More testing is needed. We may be able to remove this function in 
        future releases and just use "del object" instead 

*/
static PyObject *hashcat_reset (hashcatObject * self, PyObject * args, PyObject *kwargs)
{

  

  Py_XDECREF (self->hash);
  self->hash = Py_BuildValue("s", "");

  Py_XDECREF (self->dict1);
  self->dict1 = Py_BuildValue("s", "");

  Py_XDECREF (self->dict2);
  self->dict2 = Py_BuildValue("s", "");
  
  Py_XDECREF (self->mask);
  self->mask = Py_BuildValue("s", "");

  // Initate hashcat clean-up
  hashcat_session_destroy (self->hashcat_ctx);

  hashcat_destroy (self->hashcat_ctx);

  Py_XDECREF (self->hashcat_ctx);

  free (self->hashcat_ctx);
  
  // Create hashcat main context
  self->hashcat_ctx = (hashcat_ctx_t *) malloc (sizeof (hashcat_ctx_t));

  if (self->hashcat_ctx == NULL)
    return NULL;

  // Initialize hashcat context
  const int rc_hashcat_init = hashcat_init (self->hashcat_ctx, event);

  if (rc_hashcat_init == -1)
    return NULL;

  // Initialize the user options
  const int rc_options_init = user_options_init (self->hashcat_ctx);

  if (rc_options_init == -1)
    return NULL;

  self->user_options = self->hashcat_ctx->user_options;

  self->hc_argc = 0;
  PyList_SetSlice(self->rp_files, 0, PyList_Size(self->rp_files), NULL);

  Py_INCREF(Py_None);
  return Py_None;

}

/* Helper function to to create a new hashcat object. Called from hashcat_new() */

static hashcatObject *newhashcatObject (PyObject * arg)
{

  hashcatObject *self;

  self = PyObject_New (hashcatObject, &hashcat_Type);

  if (self == NULL)
    return NULL;

  // Create hashcat main context
  self->hashcat_ctx = (hashcat_ctx_t *) malloc (sizeof (hashcat_ctx_t));

  if (self->hashcat_ctx == NULL)
    return NULL;

  // Initialize hashcat context
  const int rc_hashcat_init = hashcat_init (self->hashcat_ctx, event);

  if (rc_hashcat_init == -1)
    return NULL;

  // Initialize the user options
  const int rc_options_init = user_options_init (self->hashcat_ctx);

  if (rc_options_init == -1)
    return NULL;

  self->user_options = self->hashcat_ctx->user_options;

  for(int i = 0; i < n_handlers; i++)
  {

    handlers[i].esignal = NULL;

  }

  self->hash = NULL;
  self->hc_argc = 0;
  self->mask = NULL;
  self->dict1 = NULL;
  self->dict2 = NULL;
  self->rp_files = PyList_New (0);
  self->event_types = PyTuple_New(N_EVENTS_TYPES);
  
  if (self->event_types == NULL)
    return NULL;

  for(int i = 0; i < N_EVENTS_TYPES; i++)
  {

    PyTuple_SET_ITEM(self->event_types, i, Py_BuildValue ("s", event_strs[i]));

  }
  return self;

}

/* Function of no arguments returning a new hashcat object Exposed as __new__() method */

static PyObject *hashcat_new (PyTypeObject * self, PyObject * noargs, PyObject * nokwds)
{
  hashcatObject *new_pyo;

  if (!PyArg_ParseTuple (noargs, ":new"))
    return NULL;

  new_pyo = newhashcatObject (noargs);

  if (new_pyo == NULL)
    return NULL;

  return (PyObject *) new_pyo;
}


/* methods */

static void hashcat_dealloc (hashcatObject * self)
{

  Py_XDECREF (self->hash);
  Py_XDECREF (self->dict1);
  Py_XDECREF (self->dict2);
  Py_XDECREF (self->mask);

  // Initate hashcat clean-up
  hashcat_session_destroy (self->hashcat_ctx);

  hashcat_destroy (self->hashcat_ctx);

  Py_XDECREF (self->hashcat_ctx);

  free (self->hashcat_ctx);

  PyObject_Del (self);

}

static void *hc_session_exe_thread(void *params)
{
 
 hashcatObject *self = (hashcatObject *) params;

 int rtn;
 rtn = hashcat_session_execute(self->hashcat_ctx);
 
 if(rtn)
  rtn = rtn;

 return NULL;

}

PyDoc_STRVAR(hashcat_session_execute__doc__,
"hashcat_session_execute -> int\n\n\
Start hashcat cracking session in background thread.\n\n\
Return 0 on successful thread creation, pthread error number otherwise");

static PyObject *hashcat_hashcat_session_execute (hashcatObject * self, PyObject * args, PyObject * kwargs)
{

  char *py_path = "/usr/bin";
  char *hc_path = "/usr/local/share/hashcat";
  static char *kwlist[] = {"py_path", "hc_path", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|ss", kwlist, &py_path, &hc_path)) 
  {
    return NULL;
  }

  // Build argv
  size_t hc_argv_size = 1;
  char **hc_argv = (char **) calloc (hc_argv_size, sizeof (char *));

  // Benchmark is a special case
  if (self->user_options->benchmark){

    self->hc_argc = 1;
    hc_argv_size = self->hc_argc + 1;
    hc_argv = (char **) realloc (hc_argv, sizeof (char *) * (hc_argv_size));
    hc_argv[0] = NULL;
    self->user_options->hc_argc = self->hc_argc;
    self->user_options->hc_argv = hc_argv;

  // Every other case need a hash source set otherwise fail
  } else if (self->hash == NULL) {

    PyErr_SetString (PyExc_RuntimeError, "Hash source not set");
    Py_INCREF (Py_None);
    return Py_None;

  } else {

    switch (self->user_options->attack_mode)
    {
  
  
    // 0 | Straight
    case 0:
  
      if (self->dict1 == NULL)
      {
  
        PyErr_SetString (PyExc_RuntimeError, "Undefined dictionary");
        Py_INCREF (Py_None);
        return Py_None;
      }
  
      self->hc_argc = 2;
      hc_argv_size = self->hc_argc + 1;
      hc_argv = (char **) realloc (hc_argv, sizeof (char *) * (hc_argv_size));
      hc_argv[0] = PyString_AsString (self->hash);
      hc_argv[1] = PyString_AsString (self->dict1);
      hc_argv[2] = NULL;
      self->user_options->hc_argc = self->hc_argc;
      self->user_options->hc_argv = hc_argv;
  
      // Set the rules files (rp_files)
      for (int i = 0; i < PyList_Size (self->rp_files); i++)
      {
  
        self->user_options->rp_files[i] = PyString_AsString (PyList_GetItem (self->rp_files, i));
      }
  
      break;
  
      // 1 | Combination
    case 1:
  
      if ((self->dict1 == NULL) || (self->dict2 == NULL))
      {
  
        PyErr_SetString (PyExc_RuntimeError, "Undefined dictionary");
        Py_INCREF (Py_None);
        return Py_None;
      }
  
      self->hc_argc = 3;
      hc_argv_size = self->hc_argc + 1;
      hc_argv = (char **) realloc (hc_argv, sizeof (char *) * (hc_argv_size));
      hc_argv[0] = PyString_AsString (self->hash);
      hc_argv[1] = PyString_AsString (self->dict1);
      hc_argv[2] = PyString_AsString (self->dict2);
      hc_argv[3] = NULL;
      self->user_options->hc_argc = self->hc_argc;
      self->user_options->hc_argv = hc_argv;
  
      break;
  
      // 3 | Bruteforce (mask)
    case 3:
  
      if (self->mask == NULL)
      {
  
        PyErr_SetString (PyExc_RuntimeError, "Undefined mask");
        Py_INCREF (Py_None);
        return Py_None;
      }
  
      self->hc_argc = 2;
      hc_argv_size = self->hc_argc + 1;
      hc_argv = (char **) realloc (hc_argv, sizeof (char *) * (hc_argv_size));
      hc_argv[0] = PyString_AsString (self->hash);
      hc_argv[1] = PyString_AsString (self->mask);
      hc_argv[2] = NULL;
      self->user_options->hc_argc = self->hc_argc;
      self->user_options->hc_argv = hc_argv;
  
      break;
  
      // 6 | Hybrid dict mask
    case 6:
  
      if (self->dict1 == NULL)
      {
  
        PyErr_SetString (PyExc_RuntimeError, "Undefined dictionary");
        Py_INCREF (Py_None);
        return Py_None;
      }
  
      if (self->mask == NULL)
      {
  
        PyErr_SetString (PyExc_RuntimeError, "Undefined mask");
        Py_INCREF (Py_None);
        return Py_None;
      }
  
      self->hc_argc = 3;
      hc_argv_size = self->hc_argc + 1;
      hc_argv = (char **) realloc (hc_argv, sizeof (char *) * (hc_argv_size));
      hc_argv[0] = PyString_AsString (self->hash);
      hc_argv[1] = PyString_AsString (self->dict1);
      hc_argv[2] = PyString_AsString (self->mask);
      hc_argv[3] = NULL;
      self->user_options->hc_argc = self->hc_argc;
      self->user_options->hc_argv = hc_argv;
  
      break;
  
      // 7 | Hybrid mask dict
    case 7:
  
      if (self->dict1 == NULL)
      {
  
        PyErr_SetString (PyExc_RuntimeError, "Undefined dictionary");
        Py_INCREF (Py_None);
        return Py_None;
      }
  
      if (self->mask == NULL)
      {
  
        PyErr_SetString (PyExc_RuntimeError, "Undefined mask");
        Py_INCREF (Py_None);
        return Py_None;
      }
  
      self->hc_argc = 3;
      hc_argv_size = self->hc_argc + 1;
      hc_argv = (char **) realloc (hc_argv, sizeof (char *) * (hc_argv_size));
      hc_argv[0] = PyString_AsString (self->hash);
      hc_argv[1] = PyString_AsString (self->mask);
      hc_argv[2] = PyString_AsString (self->dict1);
      hc_argv[3] = NULL;
      self->user_options->hc_argc = self->hc_argc;
      self->user_options->hc_argv = hc_argv;
  
      break;
  
    default:
  
      PyErr_SetString (PyExc_NotImplementedError, "Invalid Attack Mode");
      Py_INCREF (Py_None);
      return Py_None;
  
  
    }


  }

  


  /**  
   *   !! IMPORTANT !!
   *   Getting the args to hashcat_session_init correct is critical. 
   *   The first parameter is where Python is installed and
   *   the second is where you installed all the hashcat files.
   * 
   * */
  self->rc_init = hashcat_session_init (self->hashcat_ctx, py_path, hc_path, 0, NULL, 0);

  if (self->rc_init != 0)
  {

    char *msg = hashcat_get_log (self->hashcat_ctx);

    PyErr_SetString (PyExc_RuntimeError, msg);

    Py_INCREF (Py_None);
    return Py_None;

  }

  int rtn;
  pthread_t hThread;
  
  Py_BEGIN_ALLOW_THREADS

  rtn = pthread_create(&hThread, NULL, &hc_session_exe_thread, (void *)self);

  Py_END_ALLOW_THREADS


  return Py_BuildValue ("i", rtn);
}


PyDoc_STRVAR(hashcat_session_pause__doc__,
"hashcat_session_pause -> int\n\n\
Pause hashcat cracking session.\n\n\
Return 0 on success, -1 on error");

static PyObject *hashcat_hashcat_session_pause (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = hashcat_session_pause (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(hashcat_session_resume__doc__,
"hashcat_session_resume -> int\n\n\
Resume hashcat cracking session.\n\n\
Return 0 on success, -1 on error");

static PyObject *hashcat_hashcat_session_resume (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = hashcat_session_resume (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(hashcat_session_bypass__doc__,
"hashcat_session_bypass -> int\n\n\
Bypass current attack and go to next. Only applicable when using multiple wordlists or masks\n\n\
Return 0 on success, -1 on error");

static PyObject *hashcat_hashcat_session_bypass (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = hashcat_session_bypass (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(hashcat_session_checkpoint__doc__,
"hashcat_session_checkpoint -> int\n\n\
Stop at next restore point. This feature is disabled when restore_disabled is specified, and will return error\n\n\
Return 0 on success, -1 on error");

static PyObject *hashcat_hashcat_session_checkpoint (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = hashcat_session_checkpoint (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(hashcat_session_quit__doc__,
"hashcat_session_quit -> int\n\n\
Quit hashcat session.\n\n\
Return 0 on success");

static PyObject *hashcat_hashcat_session_quit (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = hashcat_session_quit (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_device_info_cnt__doc__,
"status_get_device_info_cnt -> int\n\n\
Return number of devices. (i.e. CPU, GPU, FPGA, DSP, Co-Processor)\n\n");
// More info: https://hashcat.net/forum/thread-5660.html

static PyObject *hashcat_status_get_device_info_cnt (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_device_info_cnt (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_device_info_active__doc__,
"status_get_device_info_active -> int\n\n\
Return number of active devices.\n\n");

static PyObject *hashcat_status_get_device_info_active (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_device_info_active (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_skipped_dev__doc__,
"status_get_skipped_dev(device_id) -> bool\n\n\
Return True if device status is skipped.\n\n");

static PyObject *hashcat_status_get_skipped_dev (hashcatObject * self, PyObject * args)
{

  int device_id;

  if (!PyArg_ParseTuple (args, "i", &device_id))
  {
    return NULL;
  }

  bool rtn;

  rtn = status_get_skipped_dev (self->hashcat_ctx, device_id);
  return PyBool_FromLong (rtn);
}


PyDoc_STRVAR(status_get_session__doc__,
"status_get_session -> str\n\n\
Return session string set at run time.\n\n");

static PyObject *hashcat_status_get_session (hashcatObject * self, PyObject * noargs)
{

  char *rtn;

  rtn = status_get_session (self->hashcat_ctx);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_status_string__doc__,
"status_get_skipped_dev -> str\n\n\
Return session string set at run time.\n\n\
DETAILS:\n\
\tInitializing\n\
\tAutotuning\n\
\tRunning\n\
\tPaused\n\
\tExhausted\n\
\tCracked\n\
\tAborted\n\
\tQuit\n\
\tBypass\n\
\tAborted (Checkpoint)\n\
\tAborted (Runtime)\n\
\tUnknown! Bug!\n\n");

static PyObject *hashcat_status_get_status_string (hashcatObject * self, PyObject * noargs)
{

  const char *rtn;

  rtn = status_get_status_string (self->hashcat_ctx);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_status_number__doc__,
"status_get_status_number -> int\n\n\
Return session number set at run time.\n\n\
DETAILS:\n\
\tInitializing->ST_0000\n\
\tAutotuning->ST_0001\n\
\tRunning->ST_0002\n\
\tPaused->ST_0003\n\
\tExhausted->ST_0004\n\
\tCracked->ST_0005\n\
\tAborted->ST_0006\n\
\tQuit->ST_0007\n\
\tBypass->ST_0008\n\
\tAborted (Checkpoint)->ST_0009\n\
\tAborted (Runtime)->ST_0010\n\n");

static PyObject *hashcat_status_get_status_number (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_status_number (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_guess_mode__doc__,
"status_get_guess_mode -> int\n\n\
Return input mode.\n\n\
DETAILS:\n\
\tGUESS_MODE_NONE                       = 0\n\
\tGUESS_MODE_STRAIGHT_FILE              = 1\n\
\tGUESS_MODE_STRAIGHT_FILE_RULES_FILE   = 2\n\
\tGUESS_MODE_STRAIGHT_FILE_RULES_GEN    = 3\n\
\tGUESS_MODE_STRAIGHT_STDIN             = 4\n\
\tGUESS_MODE_STRAIGHT_STDIN_RULES_FILE  = 5\n\
\tGUESS_MODE_STRAIGHT_STDIN_RULES_GEN   = 6\n\
\tGUESS_MODE_COMBINATOR_BASE_LEFT       = 7\n\
\tGUESS_MODE_COMBINATOR_BASE_RIGHT      = 8\n\
\tGUESS_MODE_MASK                       = 9\n\
\tGUESS_MODE_MASK_CS                    = 10\n\
\tGUESS_MODE_HYBRID1                    = 11\n\
\tGUESS_MODE_HYBRID1_CS                 = 12\n\
\tGUESS_MODE_HYBRID2                    = 13\n\
\tGUESS_MODE_HYBRID2_CS                 = 14\n\n");

static PyObject *hashcat_status_get_guess_mode (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_guess_mode (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_guess_base__doc__,
"status_get_guess_base -> str\n\n\
Return base input source.\n\n\
DETAILS:\n\
Depending on the mode the input base could be dict1, dict2, or mask.\n\n");

static PyObject *hashcat_status_get_guess_base (hashcatObject * self, PyObject * noargs)
{

  char *rtn;

  rtn = status_get_guess_base (self->hashcat_ctx);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_guess_base_offset__doc__,
"status_get_guess_base_offset -> int\n\nReturn base input offset.\n\n");

static PyObject *hashcat_status_get_guess_base_offset (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_guess_base_offset (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_guess_base_count__doc__,
"status_get_guess_base_count -> int\n\nReturn base input count.\n\n");

static PyObject *hashcat_status_get_guess_base_count (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_guess_base_count (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_guess_base_percent__doc__,
"status_get_guess_base_percent -> double\n\nReturn base input percent.\n\n");

static PyObject *hashcat_status_get_guess_base_percent (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_guess_base_percent (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}


PyDoc_STRVAR(status_get_guess_mod__doc__,
"status_get_guess_mod -> str\n\n\
Return input modification.\n\n\
DETAILS:\n\
Depending on the mode the mod could be rules file, dict1, dict2, or mask.\n\n");

static PyObject *hashcat_status_get_guess_mod (hashcatObject * self, PyObject * noargs)
{

  char *rtn;

  rtn = status_get_guess_mod (self->hashcat_ctx);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_guess_mod_offset__doc__,
"status_get_guess_mod_offset -> int\n\nReturn input modification offset.\n\n");

static PyObject *hashcat_status_get_guess_mod_offset (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_guess_mod_offset (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_guess_mod_count__doc__,
"status_get_guess_mod_count -> int\n\nReturn input modification count.\n\n");

static PyObject *hashcat_status_get_guess_mod_count (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_guess_mod_count (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_guess_mod_percent__doc__,
"status_get_guess_mod_percent -> double\n\nReturn input modification percent.\n\n");

static PyObject *hashcat_status_get_guess_mod_percent (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_guess_mod_percent (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_guess_charset__doc__,
"status_get_guess_charset -> str\n\n\
Return charset used during session.\n\n");

static PyObject *hashcat_status_get_guess_charset (hashcatObject * self, PyObject * noargs)
{

  char *rtn;

  rtn = status_get_guess_charset (self->hashcat_ctx);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_guess_mask_length__doc__,
"status_get_guess_mask_length -> int\n\n\
Return length of input mask.\n\n");

static PyObject *hashcat_status_get_guess_mask_length (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_guess_mask_length (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_guess_candidates_dev__doc__,
"status_get_guess_candidates_dev(device_id) -> str\n\n\
Return candidate status string for a device.\n\n");

static PyObject *hashcat_status_get_guess_candidates_dev (hashcatObject * self, PyObject * args)
{

  int device_id;

  if (!PyArg_ParseTuple (args, "i", &device_id))
  {
    return NULL;
  }

  char *rtn;

  rtn = status_get_guess_candidates_dev (self->hashcat_ctx, device_id);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_hash_type__doc__,
"status_get_hash_type -> str\n\n\
Return type of hash.\n\n");

static PyObject *hashcat_status_get_hash_type (hashcatObject * self, PyObject * noargs)
{

  const char *rtn;

  rtn = status_get_hash_type (self->hashcat_ctx);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_hash_target__doc__,
"status_get_hash_target -> str\n\n\
Return hash or hash file for current session.\n\n");

static PyObject *hashcat_status_get_hash_target (hashcatObject * self, PyObject * noargs)
{

  const char *rtn;

  rtn = status_get_hash_target (self->hashcat_ctx);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_digests_done__doc__,
"status_get_digests_done -> int\n\n\
Return number of completed digests (digests_done).\n\n");

static PyObject *hashcat_status_get_digests_done (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_digests_done (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_digests_cnt__doc__,
"status_get_digests_cnt -> int\n\n\
Return total number of digests (digests_cnt).\n\n");

static PyObject *hashcat_status_get_digests_cnt (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_digests_cnt (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_digests_percent__doc__,
"status_get_digests_percent -> double\n\n\
Return percentage of completed digests (digests_done/digests_cnt).\n\n");

static PyObject *hashcat_status_get_digests_percent (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_digests_percent (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_salts_done__doc__,
"status_get_salts_done -> int\n\n\
Return number of completed salts (salts_done).\n\n");

static PyObject *hashcat_status_get_salts_done (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_salts_done (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_salts_cnt__doc__,
"status_get_salts_cnt -> int\n\n\
Return total number of salts (salts_cnt).\n\n");

static PyObject *hashcat_status_get_salts_cnt (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_salts_cnt (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_salts_percent__doc__,
"status_get_salts_percent -> double\n\n\
Return percentage of completed salts (salts_done/salts_cnt).\n\n");

static PyObject *hashcat_status_get_salts_percent (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_salts_percent (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_msec_running__doc__,
"status_get_msec_running -> double\n\n\
Return running time in msec.\n\n");

static PyObject *hashcat_status_get_msec_running (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_msec_running (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_msec_paused__doc__,
"status_get_msec_paused -> double\n\n\
Return paused time in msec.\n\n");

static PyObject *hashcat_status_get_msec_paused (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_msec_paused (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_msec_real__doc__,
"status_get_msec_real -> double\n\n\
Return running time plus paused time in msec.\n\n");

static PyObject *hashcat_status_get_msec_real (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_msec_real (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_time_started_absolute__doc__,
"status_get_time_started_absolute -> str\n\n\
Return string representation of start time.\n\n\
DETAILS:\n\
Thu Jan 1 21:49:08 1970\n\n");

static PyObject *hashcat_status_get_time_started_absolute (hashcatObject * self, PyObject * noargs)
{

  char *rtn;

  rtn = status_get_time_started_absolute (self->hashcat_ctx);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_time_started_relative__doc__,
"status_get_time_started_relative -> str\n\n\
Return string representation of elapsed time relative to start.\n\n\
DETAILS:\n\
\t5 secs\n\
\t5 mins\n\
\t5 hours\n\
\t5 days\n\
\t5 years\n\n");

static PyObject *hashcat_status_get_time_started_relative (hashcatObject * self, PyObject * noargs)
{

  char *rtn;

  rtn = status_get_time_started_relative (self->hashcat_ctx);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_time_estimated_absolute__doc__,
"status_get_time_estimated_absolute -> str\n\n\
Return string representation of estimated time.\n\
DETAILS:\n\
Thu Jan 1 21:49:08 1970\n\n");

static PyObject *hashcat_status_get_time_estimated_absolute (hashcatObject * self, PyObject * noargs)
{

  char *rtn;

  rtn = status_get_time_estimated_absolute (self->hashcat_ctx);
  return Py_BuildValue ("c", rtn);
}

PyDoc_STRVAR(status_get_time_estimated_relative__doc__,
"status_get_time_estimated_relative -> str\n\n\
Return string representation of estimated time relative to now.\n\n\
DETAILS:\n\
\t5 secs\n\
\t5 mins\n\
\t5 hours\n\
\t5 days\n\
\t5 years\n\n");

static PyObject *hashcat_status_get_time_estimated_relative (hashcatObject * self, PyObject * noargs)
{

  char *rtn;

  rtn = status_get_time_estimated_relative (self->hashcat_ctx);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_restore_point__doc__,
"status_get_restore_point -> int\n\n\
Return restore point current position.\n\n");

static PyObject *hashcat_status_get_restore_point (hashcatObject * self, PyObject * noargs)
{

  u64 rtn;

  rtn = status_get_restore_point (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_restore_total__doc__,
"status_get_restore_total -> int\n\n\
Return total key space.\n\n");

static PyObject *hashcat_status_get_restore_total (hashcatObject * self, PyObject * noargs)
{

  u64 rtn;

  rtn = status_get_restore_total (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_restore_percent__doc__,
"status_get_restore_percent -> double\n\n\
Return percentage of keyspace covered (restore_point/restore_total).\n\n");

static PyObject *hashcat_status_get_restore_percent (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_restore_percent (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_progress_mode__doc__,
"status_get_progress_mode -> int\n\n\
Return progress mode.\n\n\
DETAILS:\n\
\tPROGRESS_MODE_NONE              = 0\n\
\tPROGRESS_MODE_KEYSPACE_KNOWN    = 1\n\
\tPROGRESS_MODE_KEYSPACE_UNKNOWN  = 2\n\n");

static PyObject *hashcat_status_get_progress_mode (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_progress_mode (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_progress_finished_percent__doc__,
"status_get_progress_finished_percent -> double\n\n\
Return progress percentage (progress_cur_relative_skip/progress_end_relative_skip).\n\n");

static PyObject *hashcat_status_get_progress_finished_percent (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_progress_finished_percent (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_progress_done__doc__,
"status_get_progress_done -> int\n\n\
Return number of password candidates attempted.\n\n");

static PyObject *hashcat_status_get_progress_done (hashcatObject * self, PyObject * noargs)
{

  u64 rtn;

  rtn = status_get_progress_done (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_progress_rejected__doc__,
"status_get_progress_rejected -> int\n\n\
Return number of password candidates rejected.\n\n");

static PyObject *hashcat_status_get_progress_rejected (hashcatObject * self, PyObject * noargs)
{

  u64 rtn;

  rtn = status_get_progress_rejected (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_progress_rejected_percent__doc__,
"status_get_progress_rejected_percent -> double\n\n\
Return percentage rejected candidates (progress_rejected/progress_cur).\n\n");

static PyObject *hashcat_status_get_progress_rejected_percent (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_progress_rejected_percent (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_progress_restored__doc__,
"status_get_progress_restored -> int\n\n\
Return restore progress completed.\n\n");

static PyObject *hashcat_status_get_progress_restored (hashcatObject * self, PyObject * noargs)
{

  u64 rtn;

  rtn = status_get_progress_restored (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_progress_cur__doc__,
"status_get_progress_cur -> int\n\n\
Return current restore progress.\n\n");

static PyObject *hashcat_status_get_progress_cur (hashcatObject * self, PyObject * noargs)
{

  u64 rtn;

  rtn = status_get_progress_cur (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_progress_end__doc__,
"status_get_progress_end -> int\n\n\
Return high limit of restore progress.\n\n");

static PyObject *hashcat_status_get_progress_end (hashcatObject * self, PyObject * noargs)
{

  u64 rtn;

  rtn = status_get_progress_end (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_progress_ignore__doc__,
"status_get_progress_ignore -> int\n\n\
Return ignore progress.\n\n");

static PyObject *hashcat_status_get_progress_ignore (hashcatObject * self, PyObject * noargs)
{

  u64 rtn;

  rtn = status_get_progress_ignore (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_progress_skip__doc__,
"status_get_progress_skip -> int\n\n\
Return skip progress.\n\n");

static PyObject *hashcat_status_get_progress_skip (hashcatObject * self, PyObject * noargs)
{

  u64 rtn;

  rtn = status_get_progress_skip (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_progress_cur_relative_skip__doc__,
"status_get_progress_cur_relative_skip -> int\n\n\
Return number of cracked hashes.\n\n");

static PyObject *hashcat_status_get_progress_cur_relative_skip (hashcatObject * self, PyObject * noargs)
{

  u64 rtn;

  rtn = status_get_progress_cur_relative_skip (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_progress_end_relative_skip__doc__,
"status_get_progress_end_relative_skip -> int\n\n\
Return total hashes targeted for cracking during session.\n\n");

static PyObject *hashcat_status_get_progress_end_relative_skip (hashcatObject * self, PyObject * noargs)
{

  u64 rtn;

  rtn = status_get_progress_end_relative_skip (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_hashes_msec_all__doc__,
"status_get_hashes_msec_all -> int\n\n\
Return total time to attempt a hash in msec for all devices.\n\n");

static PyObject *hashcat_status_get_hashes_msec_all (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_hashes_msec_all (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}


PyDoc_STRVAR(status_get_hashes_msec_dev__doc__,
"status_get_hashes_msec_dev(device_id) -> int\n\n\
Return time to attempt a hash in msec for specific device.\n\n");

static PyObject *hashcat_status_get_hashes_msec_dev (hashcatObject * self, PyObject * args)
{

  int device_id;

  if (!PyArg_ParseTuple (args, "i", &device_id))
  {
    return NULL;
  }

  double rtn;

  rtn = status_get_hashes_msec_dev (self->hashcat_ctx, device_id);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_hashes_msec_dev_benchmark__doc__,
"status_get_hashes_msec_dev_benchmark(device_id) -> int\n\n\
Return time to attempt a hash in msec for specific device (bendmark mode).\n\n");

static PyObject *hashcat_status_get_hashes_msec_dev_benchmark (hashcatObject * self, PyObject * args)
{

  int device_id;

  if (!PyArg_ParseTuple (args, "i", &device_id))
  {
    return NULL;
  }

  double rtn;

  rtn = status_get_hashes_msec_dev_benchmark (self->hashcat_ctx, device_id);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_exec_msec_all__doc__,
"status_get_exec_msec_all -> int\n\n\
Return total execution time in msec for all devices.\n\n");

static PyObject *hashcat_status_get_exec_msec_all (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_exec_msec_all (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_exec_msec_dev__doc__,
"status_get_exec_msec_dev(device_id) -> int\n\n\
Return execution time in msec for specific device.\n\n");

static PyObject *hashcat_status_get_exec_msec_dev (hashcatObject * self, PyObject * args)
{

  int device_id;

  if (!PyArg_ParseTuple (args, "i", &device_id))
  {
    return NULL;
  }

  double rtn;

  rtn = status_get_exec_msec_dev (self->hashcat_ctx, device_id);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_speed_sec_all__doc__,
"status_get_speed_sec_all(device_id) -> str\n\n\
Return total combine speed of all devices.\n\n");

static PyObject *hashcat_status_get_speed_sec_all (hashcatObject * self, PyObject * noargs)
{

  char *rtn;

  rtn = status_get_speed_sec_all (self->hashcat_ctx);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_speed_sec_dev__doc__,
"status_get_speed_sec_dev(device_id) -> str\n\n\
Return speed of device.\n\n");

static PyObject *hashcat_status_get_speed_sec_dev (hashcatObject * self, PyObject * args)
{

  int device_id;

  if (!PyArg_ParseTuple (args, "i", &device_id))
  {
    return NULL;
  }

  char *rtn;

  rtn = status_get_speed_sec_dev (self->hashcat_ctx, device_id);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_cpt_cur_min__doc__,
"status_get_cpt_cur_min -> int\n\n\
Return cracked per time (min).\n\n");

static PyObject *hashcat_status_get_cpt_cur_min (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_cpt_cur_min (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_cpt_cur_hour__doc__,
"status_get_cpt_cur_hour -> int\n\n\
Return cracked per time (hour).\n\n");

static PyObject *hashcat_status_get_cpt_cur_hour (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_cpt_cur_hour (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_cpt_cur_day__doc__,
"status_get_cpt_cur_day -> int\n\n\
Return cracked per time (day).\n\n");

static PyObject *hashcat_status_get_cpt_cur_day (hashcatObject * self, PyObject * noargs)
{

  int rtn;

  rtn = status_get_cpt_cur_day (self->hashcat_ctx);
  return Py_BuildValue ("i", rtn);
}

PyDoc_STRVAR(status_get_cpt_avg_min__doc__,
"status_get_cpt_avg_min -> double\n\n\
Return averaged cracked per time (min).\n\n");

static PyObject *hashcat_status_get_cpt_avg_min (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_cpt_avg_min (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_cpt_avg_hour__doc__,
"status_get_cpt_avg_hour -> double\n\n\
Return averaged cracked per time (hour).\n\n");

static PyObject *hashcat_status_get_cpt_avg_hour (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_cpt_avg_hour (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_cpt_avg_day__doc__,
"status_get_cpt_avg_day -> double\n\n\
Return averaged cracked per time (day).\n\n");

static PyObject *hashcat_status_get_cpt_avg_day (hashcatObject * self, PyObject * noargs)
{

  double rtn;

  rtn = status_get_cpt_avg_day (self->hashcat_ctx);
  return Py_BuildValue ("d", rtn);
}

PyDoc_STRVAR(status_get_cpt__doc__,
"status_get_cpt -> str\n\n\
Return string representation of cracked stats.\n\n");

static PyObject *hashcat_status_get_cpt (hashcatObject * self, PyObject * noargs)
{

  char *rtn;

  rtn = status_get_cpt (self->hashcat_ctx);
  return Py_BuildValue ("s", rtn);
}

PyDoc_STRVAR(status_get_hwmon_dev__doc__,
"status_get_hwmon_dev(device_id) -> str\n\n\
Return device stats.\n\n\
DETAILS:\n\
\tTemp\n\
\tFan\n\
\tUtil\n\
\tCore (Mhz)\n\
\tMem\n\
\tLanes\n\
\tN/A\n\n");

static PyObject *hashcat_status_get_hwmon_dev (hashcatObject * self, PyObject * args)
{

  int device_id;

  if (!PyArg_ParseTuple (args, "i", &device_id))
  {
    return NULL;
  }

  char *rtn;

  rtn = status_get_hwmon_dev (self->hashcat_ctx, device_id);
  return Py_BuildValue ("s", rtn);

}

PyDoc_STRVAR(status_get_corespeed_dev__doc__,
"status_get_corespeed_dev(device_id) -> int\n\nReturn device corespeed.\n\n");

static PyObject *hashcat_status_get_corespeed_dev (hashcatObject * self, PyObject * args)
{

  int device_id;

  if (!PyArg_ParseTuple (args, "i", &device_id))
  {
    return NULL;
  }

  int rtn;

  rtn = status_get_corespeed_dev (self->hashcat_ctx, device_id);
  return Py_BuildValue ("i", rtn);

}

PyDoc_STRVAR(status_get_memoryspeed_dev__doc__,
"status_get_memoryspeed_dev(device_id) -> int\n\nReturn device memoryspeed.\n\n");

static PyObject *hashcat_status_get_memoryspeed_dev (hashcatObject * self, PyObject * args)
{

  int device_id;

  if (!PyArg_ParseTuple (args, "i", &device_id))
  {
    return NULL;
  }

  int rtn;

  rtn = status_get_memoryspeed_dev (self->hashcat_ctx, device_id);
  return Py_BuildValue ("i", rtn);

}

PyDoc_STRVAR(status_get_progress_dev__doc__,
"status_get_progress_dev(device_id) -> int\n\nReturn device progress (keyspace).\n\n");

static PyObject *hashcat_status_get_progress_dev (hashcatObject * self, PyObject * args)
{

  int device_id;

  if (!PyArg_ParseTuple (args, "i", &device_id))
  {
    return NULL;
  }

  int rtn;

  rtn = status_get_progress_dev (self->hashcat_ctx, device_id);
  return Py_BuildValue ("i", rtn);

}

PyDoc_STRVAR(status_get_runtime_msec_dev__doc__,
"status_get_runtime_msec_dev(device_id) -> double\n\nReturn device runtime (ms).\n\n");

static PyObject *hashcat_status_get_runtime_msec_dev (hashcatObject * self, PyObject * args)
{

  int device_id;

  if (!PyArg_ParseTuple (args, "i", &device_id))
  {
    return NULL;
  }

  double rtn;

  rtn = status_get_runtime_msec_dev (self->hashcat_ctx, device_id);
  return Py_BuildValue ("d", rtn);

}


PyDoc_STRVAR(hash__doc__,
"hash\tstr\thash|hashfile|hccapfile\n\n");

static PyObject *hashcat_gethash (hashcatObject * self)
{

  if (self->hash == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return self->hash;

}


static int hashcat_sethash (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete hash attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The hash attribute value must be a string");
    return -1;
  }

  Py_XDECREF (self->hash);
  Py_INCREF (value);            // Increment the value or garbage collection will eat it
  self->hash = value;

  return 0;

}

PyDoc_STRVAR(dict1__doc__,
"dict1\tstr\tdictionary|directory\n\n");

static PyObject *hashcat_getdict1 (hashcatObject * self)
{

  if (self->dict1 == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return self->dict1;

}


static int hashcat_setdict1 (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete dict1 attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The dict1 attribute value must be a string");
    return -1;
  }

  Py_XDECREF (self->dict1);
  Py_INCREF (value);            // Increment the value or garbage collection will eat it
  self->dict1 = value;

  return 0;

}

PyDoc_STRVAR(dict2__doc__,
"dict2\tstr\tdictionary\n\n");

static PyObject *hashcat_getdict2 (hashcatObject * self)
{

  if (self->dict2 == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return self->dict2;

}


static int hashcat_setdict2 (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete dict2 attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The dict2 attribute value must be a string");
    return -1;
  }

  Py_XDECREF (self->dict2);
  Py_INCREF (value);            // Increment the value or garbage collection will eat it
  self->dict2 = value;

  return 0;

}

PyDoc_STRVAR(mask__doc__,
"mask\tstr\tmask|directory\n\n");

static PyObject *hashcat_getmask (hashcatObject * self)
{

  if (self->mask == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return self->mask;

}


static int hashcat_setmask (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete mask attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The mask attribute value must be a string");
    return -1;
  }

  Py_XDECREF (self->mask);
  Py_INCREF (value);            // Increment the value or garbage collection will eat it
  self->mask = value;

  return 0;

}

PyDoc_STRVAR(attack_mode__doc__,
"attack_mode\tint\tSee reference below\n\n\
Reference:\n\
\t0 | Straight\n\
\t1 | Combination\n\
\t3 | Brute-force\n\
\t6 | Hybrid Wordlist + Mask\n\
\t7 | Hybrid Mask + Wordlist\n\n");

// getter - attack_mode
static PyObject *hashcat_getattack_mode (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->attack_mode);

}

// setter - attack_mode
static int hashcat_setattack_mode (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete attack_mode attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The attack_mode attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->attack_mode = PyInt_AsLong (value);

  return 0;

}


PyDoc_STRVAR(benchmark__doc__,
"benchmark\tbool\tRun benchmark\n\n");

// getter - benchmark
static PyObject *hashcat_getbenchmark (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->benchmark);

}

// setter - benchmark
static int hashcat_setbenchmark (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete benchmark attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The benchmark attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->benchmark = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->benchmark = 0;

  }



  return 0;

}

PyDoc_STRVAR(bitmap_max__doc__,
"bitmap_max\tint\tSets maximum bits allowed for bitmaps to X \n\n");

// getter - bitmap_max
static PyObject *hashcat_getbitmap_max (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->bitmap_max);

}

// setter - bitmap_max
static int hashcat_setbitmap_max (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete bitmap_max attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The bitmap_max attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->bitmap_max = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(bitmap_min__doc__,
"bitmap_min\tint\tSets minimum bits allowed for bitmaps to X\n\n");

// getter - bitmap_min
static PyObject *hashcat_getbitmap_min (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->bitmap_min);

}

// setter - bitmap_min
static int hashcat_setbitmap_min (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete bitmap_min attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The bitmap_min attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->bitmap_min = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(cpu_affinity__doc__,
"cpu_affinity\tstr\tLocks to CPU devices, separate with comma\n\n");

// getter - cpu_affinity
static PyObject *hashcat_getcpu_affinity (hashcatObject * self)
{

  if (self->user_options->cpu_affinity == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->cpu_affinity);

}

// setter - cpu_affinity
static int hashcat_setcpu_affinity (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete cpu_affinity attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The cpu_affinity attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->cpu_affinity = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(custom_charset_1__doc__,
"custom_charset_1\tstr\t User-defined charset ?1\n\n");

// getter - custom_charset_1
static PyObject *hashcat_getcustom_charset_1 (hashcatObject * self)
{

  if (self->user_options->custom_charset_1 == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->custom_charset_1);

}

// setter - custom_charset_1
static int hashcat_setcustom_charset_1 (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete custom_charset_1 attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The custom_charset_1 attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->custom_charset_1 = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(custom_charset_2__doc__,
"custom_charset_2\tstr\t User-defined charset ?2\n\n");

// getter - custom_charset_2
static PyObject *hashcat_getcustom_charset_2 (hashcatObject * self)
{

  if (self->user_options->custom_charset_2 == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->custom_charset_2);

}

// setter - custom_charset_2
static int hashcat_setcustom_charset_2 (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete custom_charset_2 attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The custom_charset_2 attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->custom_charset_2 = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(custom_charset_3__doc__,
"custom_charset_3\tstr\t User-defined charset ?3\n\n");

// getter - custom_charset_3
static PyObject *hashcat_getcustom_charset_3 (hashcatObject * self)
{

  if (self->user_options->custom_charset_3 == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->custom_charset_3);

}

// setter - custom_charset_3
static int hashcat_setcustom_charset_3 (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete custom_charset_3 attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The custom_charset_3 attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->custom_charset_3 = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(custom_charset_4__doc__,
"custom_charset_4\tstr\t User-defined charset ?4\n\n");

// getter - custom_charset_4
static PyObject *hashcat_getcustom_charset_4 (hashcatObject * self)
{

  if (self->user_options->custom_charset_4 == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->custom_charset_4);

}

// setter - custom_charset_4
static int hashcat_setcustom_charset_4 (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete custom_charset_4 attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The custom_charset_4 attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->custom_charset_4 = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(debug_file__doc__,
"debug_file\tstr\tOutput file for debugging rules\n\n");

// getter - debug_file
static PyObject *hashcat_getdebug_file (hashcatObject * self)
{

  if (self->user_options->debug_file == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->debug_file);

}

// setter - debug_file
static int hashcat_setdebug_file (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete debug_file attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The debug_file attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->debug_file = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(debug_mode__doc__,
"debug_mode\tint\tDefines the debug mode (hybrid only by using rules) \n\n\
REFERENCE:\n\
\t1 | Finding-Rule\n\
\t2 | Original-Word\n\
\t3 | Original-Word:Finding-Rule\n\
\t4 | Original-Word:Finding-Rule:Processed-Word\n\n");

// getter - debug_mode
static PyObject *hashcat_getdebug_mode (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->debug_mode);

}

// setter - debug_mode
static int hashcat_setdebug_mode (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete debug_mode attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The debug_mode attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->debug_mode = PyInt_AsLong (value);

  return 0;

}


PyDoc_STRVAR(force__doc__,
"force\tbool\tIgnore warnings\n\n");

// getter - force
static PyObject *hashcat_getforce (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->force);

}

// setter - force
static int hashcat_setforce (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete force attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The force attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->force = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->force = 0;

  }



  return 0;

}


PyDoc_STRVAR(gpu_temp_abort__doc__,
"gpu_temp_abort\tint\tAbort if GPU temperature reaches X degrees celsius\n\n");

// getter - gpu_temp_abort
static PyObject *hashcat_getgpu_temp_abort (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->gpu_temp_abort);

}

// setter - gpu_temp_abort
static int hashcat_setgpu_temp_abort (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete gpu_temp_abort attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The gpu_temp_abort attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->gpu_temp_abort = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(gpu_temp_disable__doc__,
"gpu_temp_disable\tbool\tDisable temperature and fanspeed reads and triggers\n\n");

// getter - gpu_temp_disable
static PyObject *hashcat_getgpu_temp_disable (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->gpu_temp_disable);

}

// setter - gpu_temp_disable
static int hashcat_setgpu_temp_disable (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete gpu_temp_disable attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The gpu_temp_disable attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->gpu_temp_disable = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->gpu_temp_disable = 0;

  }



  return 0;

}




PyDoc_STRVAR(hash_mode__doc__,
"hash_mode\tint\tHash-type, see references\n\n");

// getter - hash_mode
static PyObject *hashcat_gethash_mode (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->hash_mode);

}

// setter - hash_mode
static int hashcat_sethash_mode (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete hash_mode attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The hash_mode attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->hash_mode = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(hex_charset__doc__,
"hex_charset\tbool\tAssume charset is given in hex\n\n");

// getter - hex_charset
static PyObject *hashcat_gethex_charset (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->hex_charset);

}

// setter - hex_charset
static int hashcat_sethex_charset (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete hex_charset attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The hex_charset attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->hex_charset = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->hex_charset = 0;

  }



  return 0;

}

PyDoc_STRVAR(hex_salt__doc__,
"hex_salt\tbool\tAssume salt is given in hex\n\n");

// getter - hex_salt
static PyObject *hashcat_gethex_salt (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->hex_salt);

}

// setter - hex_salt
static int hashcat_sethex_salt (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete hex_salt attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The hex_salt attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->hex_salt = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->hex_salt = 0;

  }



  return 0;

}


PyDoc_STRVAR(hex_wordlist__doc__,
"hex_wordlist\tbool\tAssume words in wordlist is given in hex\n\n");

// getter - hex_wordlist
static PyObject *hashcat_gethex_wordlist (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->hex_wordlist);

}

// setter - hex_wordlist
static int hashcat_sethex_wordlist (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete hex_wordlist attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The hex_wordlist attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->hex_wordlist = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->hex_wordlist = 0;

  }



  return 0;

}



PyDoc_STRVAR(increment__doc__,
"increment\tbool\tEnable mask increment mode\n\n");

// getter - increment
static PyObject *hashcat_getincrement (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->increment);

}

// setter - increment
static int hashcat_setincrement (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete increment attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The increment attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->increment = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->increment = 0;

  }



  return 0;

}


PyDoc_STRVAR(increment_max__doc__,
"increment_max\tint\tStop mask incrementing at X\n\n");

// getter - increment_max
static PyObject *hashcat_getincrement_max (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->increment_max);

}

// setter - increment_max
static int hashcat_setincrement_max (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete increment_max attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The increment_max attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->increment_max = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(increment_min__doc__,
"increment_min\tint\tStart mask incrementing at X\n\n");

// getter - increment_min
static PyObject *hashcat_getincrement_min (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->increment_min);

}

// setter - increment_min
static int hashcat_setincrement_min (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete increment_min attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The increment_min attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->increment_min = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(induction_dir__doc__,
"induction_dir\tstr\tSpecify the induction directory to use for loopback\n\n");

// getter - induction_dir
static PyObject *hashcat_getinduction_dir (hashcatObject * self)
{

  if (self->user_options->induction_dir == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->induction_dir);

}

// setter - induction_dir
static int hashcat_setinduction_dir (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete induction_dir attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The induction_dir attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->induction_dir = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(keep_guessing__doc__,
"keep_guessing\tbool\tKeep guessing the hash after it has been cracked\n\n");

// getter - keep_guessing
static PyObject *hashcat_getkeep_guessing (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->keep_guessing);

}

// setter - keep_guessing
static int hashcat_setkeep_guessing (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete keep_guessing attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The keep_guessing attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->keep_guessing = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->keep_guessing = 0;

  }



  return 0;

}


PyDoc_STRVAR(kernel_accel__doc__,
"kernel_accel\tint\tManual workload tuning, set outerloop step size to X\n\n");

// getter - kernel_accel
static PyObject *hashcat_getkernel_accel (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->kernel_accel);

}

// setter - kernel_accel
static int hashcat_setkernel_accel (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete kernel_accel attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The kernel_accel attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->kernel_accel = PyInt_AsLong (value);

  return 0;

}


PyDoc_STRVAR(kernel_loops__doc__,
"kernel_loops\tint\tManual workload tuning, set innerloop step size to X\n\n");

// getter - kernel_loops
static PyObject *hashcat_getkernel_loops (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->kernel_loops);

}

// setter - kernel_loops
static int hashcat_setkernel_loops (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete kernel_loops attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The kernel_loops attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->kernel_loops = PyInt_AsLong (value);

  return 0;

}


PyDoc_STRVAR(keyspace__doc__,
"keyspace\tbool\tShow keyspace base:mod values and quit\n\n");

// getter - keyspace
static PyObject *hashcat_getkeyspace (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->keyspace);

}

// setter - keyspace
static int hashcat_setkeyspace (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete keyspace attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The keyspace attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->keyspace = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->keyspace = 0;

  }



  return 0;

}

PyDoc_STRVAR(left__doc__,
"left\tstr\tSingle rule applied to each word from left wordlist\n\n");

// getter - left
static PyObject *hashcat_getleft (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->left);

}

// setter - left
static int hashcat_setleft (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete left attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The left attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->left = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->left = 0;

  }



  return 0;

}


PyDoc_STRVAR(limit__doc__,
"limit\tint\tLimit X words from the start + skipped words\n\n");

// getter - limit
static PyObject *hashcat_getlimit (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->limit);

}

// setter - limit
static int hashcat_setlimit (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete limit attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The limit attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->limit = PyInt_AsLong (value);

  return 0;

}


PyDoc_STRVAR(logfile_disable__doc__,
"logfile_disable\tbool\tDisable the logfile\n\n");

// getter - logfile_disable
static PyObject *hashcat_getlogfile_disable (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->logfile_disable);

}

// setter - logfile_disable
static int hashcat_setlogfile_disable (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete logfile_disable attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The logfile_disable attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->logfile_disable = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->logfile_disable = 0;

  }



  return 0;

}



PyDoc_STRVAR(loopback__doc__,
"loopback\tbool\tAdd new plains to induct directory\n\n");

// getter - loopback
static PyObject *hashcat_getloopback (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->loopback);

}

// setter - loopback
static int hashcat_setloopback (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete loopback attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The loopback attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->loopback = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->loopback = 0;

  }



  return 0;

}

PyDoc_STRVAR(machine_readable__doc__,
"machine_readable\tbool\tDisplay the status view in a machine readable format\n\n");

// getter - machine_readable
static PyObject *hashcat_getmachine_readable (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->machine_readable);

}

// setter - machine_readable
static int hashcat_setmachine_readable (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete machine_readable attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The machine_readable attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->machine_readable = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->machine_readable = 0;

  }



  return 0;

}


PyDoc_STRVAR(markov_classic__doc__,
"markov_classic\tbool\tEnables classic markov-chains, no per-position\n\n");

// getter - markov_classic
static PyObject *hashcat_getmarkov_classic (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->markov_classic);

}

// setter - markov_classic
static int hashcat_setmarkov_classic (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete markov_classic attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The markov_classic attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->markov_classic = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->markov_classic = 0;

  }



  return 0;

}

PyDoc_STRVAR(markov_disable__doc__,
"markov_disable\tbool\tDisables markov-chains, emulates classic brute-force\n\n");

// getter - markov_disable
static PyObject *hashcat_getmarkov_disable (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->markov_disable);

}

// setter - markov_disable
static int hashcat_setmarkov_disable (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete markov_disable attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The markov_disable attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->markov_disable = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->markov_disable = 0;

  }



  return 0;

}

PyDoc_STRVAR(markov_hcstat__doc__,
"markov_hcstat\tstr\tSpecify hcstat file to use\n\n");

// getter - markov_hcstat
static PyObject *hashcat_getmarkov_hcstat (hashcatObject * self)
{

  if (self->user_options->markov_hcstat == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->markov_hcstat);

}

// setter - markov_hcstat
static int hashcat_setmarkov_hcstat (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete markov_hcstat attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The markov_hcstat attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->markov_hcstat = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(markov_threshold__doc__,
"markov_threshold\tint\tThreshold X when to stop accepting new markov-chains\n\n");

// getter - markov_threshold
static PyObject *hashcat_getmarkov_threshold (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->markov_threshold);

}

// setter - markov_threshold
static int hashcat_setmarkov_threshold (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete markov_threshold attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The markov_threshold attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->markov_threshold = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(nvidia_spin_damp__doc__,
"nvidia_spin_damp\tint\tWorkaround NVidias CPU burning loop bug, in percent\n\n");

// getter - nvidia_spin_damp
static PyObject *hashcat_getnvidia_spin_damp (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->nvidia_spin_damp);

}

// setter - nvidia_spin_damp
static int hashcat_setnvidia_spin_damp (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete nvidia_spin_damp attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The nvidia_spin_damp attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->nvidia_spin_damp = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(opencl_device_types__doc__,
"opencl_device_types\tstr\tOpenCL device-types to use, separate with comma\n\n\
REFERENCE:\n\
\t1 | CPU\n\
\t2 | GPU\n\
\t3 | FPGA, DSP, Co-Processor\n\n");

// getter - opencl_device_types
static PyObject *hashcat_getopencl_device_types (hashcatObject * self)
{

  if (self->user_options->opencl_device_types == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->opencl_device_types);

}

// setter - opencl_device_types
static int hashcat_setopencl_device_types (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete opencl_device_types attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The opencl_device_types attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->opencl_device_types = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(opencl_devices__doc__,
"opencl_devices\tstr\tOpenCL devices to use, separate with comma\n\n");

// getter - opencl_devices
static PyObject *hashcat_getopencl_devices (hashcatObject * self)
{

  if (self->user_options->opencl_devices == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->opencl_devices);

}

// setter - opencl_devices
static int hashcat_setopencl_devices (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete opencl_devices attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The opencl_devices attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->opencl_devices = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(opencl_info__doc__,
"opencl_info\tbool\tShow info about OpenCL platforms/devices detected\n\n");

// getter - opencl_info
static PyObject *hashcat_getopencl_info (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->opencl_info);

}

// setter - opencl_info
static int hashcat_setopencl_info (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete opencl_info attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The opencl_info attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->opencl_info = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->opencl_info = 0;

  }



  return 0;

}

PyDoc_STRVAR(opencl_platforms__doc__,
"opencl_platforms\tstr\tOpenCL platforms to use, separate with comma\n\n");

// getter - opencl_platforms
static PyObject *hashcat_getopencl_platforms (hashcatObject * self)
{

  if (self->user_options->opencl_platforms == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->opencl_platforms);

}

// setter - opencl_platforms
static int hashcat_setopencl_platforms (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete opencl_platforms attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The opencl_platforms attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->opencl_platforms = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(opencl_vector_width__doc__,
"opencl_vector_width\tint\tManual override OpenCL vector-width to X\n\n");

// getter - opencl_vector_width
static PyObject *hashcat_getopencl_vector_width (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->opencl_vector_width);

}

// setter - opencl_vector_width
static int hashcat_setopencl_vector_width (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete opencl_vector_width attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The opencl_vector_width attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->opencl_vector_width = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(outfile__doc__,
"outfile\tstr\tDefine outfile for recovered hash\n\n");

// getter - outfile
static PyObject *hashcat_getoutfile (hashcatObject * self)
{

  if (self->user_options->outfile == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->outfile);

}

// setter - outfile
static int hashcat_setoutfile (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete outfile attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The outfile attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->outfile = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(outfile_autohex__doc__,
"outfile_autohex\tbool\tDisable the use of $HEX[] in output plains\n\n");

// getter - outfile_autohex
static PyObject *hashcat_getoutfile_autohex (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->outfile_autohex);

}

// setter - outfile_autohex
static int hashcat_setoutfile_autohex (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete outfile_autohex attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The outfile_autohex attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->outfile_autohex = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->outfile_autohex = 0;

  }



  return 0;

}


PyDoc_STRVAR(outfile_check_dir__doc__,
"outfile_check_dir\tstr\tSpecify the outfile directory to monitor for plains\n\n");

// getter - outfile_check_dir
static PyObject *hashcat_getoutfile_check_dir (hashcatObject * self)
{

  if (self->user_options->outfile_check_dir == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->outfile_check_dir);

}

// setter - outfile_check_dir
static int hashcat_setoutfile_check_dir (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete outfile_check_dir attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The outfile_check_dir attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->outfile_check_dir = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(outfile_check_timer__doc__,
"outfile_check_timer\tint\tSets seconds between outfile checks to X\n\n");

// getter - outfile_check_timer
static PyObject *hashcat_getoutfile_check_timer (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->outfile_check_timer);

}

// setter - outfile_check_timer
static int hashcat_setoutfile_check_timer (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete outfile_check_timer attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The outfile_check_timer attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->outfile_check_timer = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(outfile_format__doc__,
"outfile_format\tint\tDefine outfile-format X for recovered hash\n\n\
REFERENCE:\n\
\t1  | hash[:salt]\n\
\t2  | plain\n\
\t3  | hash[:salt]:plain\n\
\t4  | hex_plain\n\
\t5  | hash[:salt]:hex_plain\n\
\t6  | plain:hex_plain\n\
\t7  | hash[:salt]:plain:hex_plain\n\
\t8  | crackpos\n\
\t9  | hash[:salt]:crack_pos\n\
\t10 | plain:crack_pos\n\
\t11 | hash[:salt]:plain:crack_pos\n\
\t12 | hex_plain:crack_pos\n\
\t13 | hash[:salt]:hex_plain:crack_pos\n\
\t14 | plain:hex_plain:crack_pos\n\
\t15 | hash[:salt]:plain:hex_plain:crack_pos\n\n");

// getter - outfile_format
static PyObject *hashcat_getoutfile_format (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->outfile_format);

}

// setter - outfile_format
static int hashcat_setoutfile_format (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete outfile_format attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The outfile_format attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->outfile_format = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(potfile_disable__doc__,
"potfile_disable\tbool\tDo not write potfile\n\n");

// getter - potfile_disable
static PyObject *hashcat_getpotfile_disable (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->potfile_disable);

}

// setter - potfile_disable
static int hashcat_setpotfile_disable (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete potfile_disable attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The potfile_disable attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->potfile_disable = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->potfile_disable = 0;

  }



  return 0;

}

PyDoc_STRVAR(potfile_path__doc__,
"potfile_path\tstr\tSpecific path to potfile\n\n");

// getter - potfile_path
static PyObject *hashcat_getpotfile_path (hashcatObject * self)
{

  if (self->user_options->potfile_path == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->potfile_path);

}

// setter - potfile_path
static int hashcat_setpotfile_path (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete potfile_path attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The potfile_path attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->potfile_path = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(quiet__doc__,
"quiet\tbool\tSuppress output\n\n");

// getter - quiet 
// NOTE: Not sure if this is necessary. Need to determine where stdout goes for Python external libs
static PyObject *hashcat_getquiet (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->quiet);

}

// setter - quiet
static int hashcat_setquiet (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete quiet attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The quiet attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->quiet = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->quiet = 0;

  }



  return 0;

}

PyDoc_STRVAR(remove__doc__,
"remove\tbool\tEnable remove of hash once it is cracked\n\n");

// getter - remove
static PyObject *hashcat_getremove (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->remove);

}

// setter - remove
static int hashcat_setremove (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete remove attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The remove attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->remove = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->remove = 0;

  }



  return 0;

}

PyDoc_STRVAR(remove_timer__doc__,
"remove_timer\tint\tUpdate input hash file each X seconds\n\n");

// getter - remove_timer
static PyObject *hashcat_getremove_timer (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->remove_timer);

}

// setter - remove_timer
static int hashcat_setremove_timer (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete remove_timer attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The remove_timer attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->remove_timer = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(restore__doc__,
"restore\tbool\tRestore session from session = \"session name\"\n\n");

// getter - restore
static PyObject *hashcat_getrestore (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->restore);

}

// setter - restore
static int hashcat_setrestore (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete restore attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The restore attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->restore = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->restore = 0;

  }



  return 0;

}

PyDoc_STRVAR(restore_disable__doc__,
"restore_disable\tbool\tDo not write restore file\n\n");

// getter - restore_disable
static PyObject *hashcat_getrestore_disable (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->restore_disable);

}

// setter - restore_disable
static int hashcat_setrestore_disable (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete restore_disable attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The restore_disable attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->restore_disable = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->restore_disable = 0;

  }



  return 0;

}

PyDoc_STRVAR(restore_file_path__doc__,
"restore_file_path\tbool\tSpecific path to restore file\n\n");

// getter - restore_file_path
static PyObject *hashcat_getrestore_file_path (hashcatObject * self)
{

  if (self->user_options->restore_file_path == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->restore_file_path);

}

// setter - restore_file_path
static int hashcat_setrestore_file_path (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete restore_file_path attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The restore_file_path attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->restore_file_path = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(restore_timer__doc__,
"restore_timer\tint\tTBD\n\n");

// getter - restore_timer
// NOTE: restore_timer may need to be removed. It's included in user_options struct in libs,
//       but it doesn't look to be an option that should be available to the users
static PyObject *hashcat_getrestore_timer (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->restore_timer);

}

// setter - restore_timer
static int hashcat_setrestore_timer (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete restore_timer attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The restore_timer attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->restore_timer = PyInt_AsLong (value);

  return 0;

}


PyDoc_STRVAR(rp_gen__doc__,
"rp_gen\tint\tGenerate X random rules\n\n");

// getter - rp_gen
static PyObject *hashcat_getrp_gen (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->rp_gen);

}

// setter - rp_gen
static int hashcat_setrp_gen (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete rp_gen attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The rp_gen attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->rp_gen = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(rp_gen_func_max__doc__,
"rp_gen_func_max\tint\tForce max X funcs per rule\n\n");

// getter - rp_gen_func_max
static PyObject *hashcat_getrp_gen_func_max (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->rp_gen_func_max);

}

// setter - rp_gen_func_max
static int hashcat_setrp_gen_func_max (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete rp_gen_func_max attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The rp_gen_func_max attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->rp_gen_func_max = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(rp_gen_func_min__doc__,
"rp_gen_func_min\tint\tForce min X funcs per rule\n\n");

// getter - rp_gen_func_min
static PyObject *hashcat_getrp_gen_func_min (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->rp_gen_func_min);

}

// setter - rp_gen_func_min
static int hashcat_setrp_gen_func_min (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete rp_gen_func_min attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The rp_gen_func_min attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->rp_gen_func_min = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(rp_gen_seed__doc__,
"rp_gen_seed\tint\tForce RNG seed set to X\n\n");

// getter - rp_gen_seed
static PyObject *hashcat_getrp_gen_seed (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->rp_gen_seed);

}

// setter - rp_gen_seed
static int hashcat_setrp_gen_seed (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete rp_gen_seed attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The rp_gen_seed attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->rp_gen_seed = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(rule_buf_l__doc__,
"rule_buf_l\tstr\tSingle rule applied to each word from left wordlist\n\n");

// getter - rule_buf_l
static PyObject *hashcat_getrule_buf_l (hashcatObject * self)
{

  if (self->user_options->rule_buf_l == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->rule_buf_l);

}

// setter - rule_buf_l
static int hashcat_setrule_buf_l (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete rule_buf_l attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The rule_buf_l attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->rule_buf_l = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(rule_buf_r__doc__,
"rule_buf_r\tstr\tSingle rule applied to each word from right wordlist\n\n");

// getter - rule_buf_r
static PyObject *hashcat_getrule_buf_r (hashcatObject * self)
{

  if (self->user_options->rule_buf_r == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->rule_buf_r);

}

// setter - rule_buf_r
static int hashcat_setrule_buf_r (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete rule_buf_r attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The rule_buf_r attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->rule_buf_r = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(runtime__doc__,
"runtime\tint\tAbort session after X seconds of runtime\n\n");

// getter - runtime
static PyObject *hashcat_getruntime (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->runtime);

}

// setter - runtime
static int hashcat_setruntime (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete runtime attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The runtime attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->runtime = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(scrypt_tmto__doc__,
"scrypt_tmto\tint\tManually override TMTO value for scrypt to X\n\n");

// getter - scrypt_tmto
static PyObject *hashcat_getscrypt_tmto (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->scrypt_tmto);

}

// setter - scrypt_tmto
static int hashcat_setscrypt_tmto (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete scrypt_tmto attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The scrypt_tmto attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->scrypt_tmto = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(segment_size__doc__,
"segment_size\tint\tSets size in MB to cache from the wordfile to X\n\n");

// getter - segment_size
static PyObject *hashcat_getsegment_size (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->segment_size);

}

// setter - segment_size
static int hashcat_setsegment_size (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete segment_size attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The segment_size attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->segment_size = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(separator__doc__,
"separator\tchar\tSeparator char for hashlists and outfile\n\n");

// getter - separator
static PyObject *hashcat_getseparator (hashcatObject * self)
{

  return Py_BuildValue ("c", self->user_options->separator);

}

// setter - separator
static int hashcat_setseparator (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete separator attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The separator attribute value must be a string");
    return -1;
  }

  char sep;

  sep = (PyString_AsString (value))[0];
  self->user_options->separator = (char) sep;

  return 0;

}

PyDoc_STRVAR(session__doc__,
"session\tstr\tDefine specific session name\n\n");

// getter - session
static PyObject *hashcat_getsession (hashcatObject * self)
{

  if (self->user_options->session == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->session);

}

// setter - session
static int hashcat_setsession (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete session attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The session attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->session = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(show__doc__,
"show\tbool\tCompare hashlist with potfile; Show cracked hashes\n\n");

// getter - show
static PyObject *hashcat_getshow (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->show);

}

// setter - show
static int hashcat_setshow (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete show attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The show attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->show = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->show = 0;

  }



  return 0;

}

PyDoc_STRVAR(skip__doc__,
"skip\tint\tSkip X words from the start\n\n");

// getter - skip
static PyObject *hashcat_getskip (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->skip);

}

// setter - skip
static int hashcat_setskip (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete skip attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The skip attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->skip = PyInt_AsLong (value);

  return 0;

}

PyDoc_STRVAR(speed_only__doc__,
"speed_only\tbool\tReturn expected speed of the attack and quit\n\n");

// getter - speed_only
static PyObject *hashcat_getspeed_only (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->speed_only);

}

// setter - speed_only
static int hashcat_setspeed_only (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete speed_only attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The speed_only attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->speed_only = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->speed_only = 0;

  }



  return 0;

}

PyDoc_STRVAR(progress_only__doc__,
"progress_only\tbool\tQuickly provides ideal progress step size and time to process on the user hashes and selected options, then quit\n\n");

// getter - progress_only
static PyObject *hashcat_getprogress_only (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->progress_only);

}

// setter - progress_only
static int hashcat_setprogress_only (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete progress_only attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The progress_only attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->progress_only = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->progress_only = 0;

  }



  return 0;

}


PyDoc_STRVAR(truecrypt_keyfiles__doc__,
"truecrypt_keyfiles\tstr\tKeyfiles used, separate with comma\n\n");

// getter - truecrypt_keyfiles
static PyObject *hashcat_gettruecrypt_keyfiles (hashcatObject * self)
{

  if (self->user_options->truecrypt_keyfiles == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->truecrypt_keyfiles);

}

// setter - truecrypt_keyfiles
static int hashcat_settruecrypt_keyfiles (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete truecrypt_keyfiles attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The truecrypt_keyfiles attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->truecrypt_keyfiles = PyString_AsString (value);

  return 0;

}


PyDoc_STRVAR(username__doc__,
"username\tbool\tEnable ignoring of usernames in hashfile\n\n");

// getter - username
static PyObject *hashcat_getusername (hashcatObject * self)
{

  return PyBool_FromLong (self->user_options->username);

}

// setter - username
static int hashcat_setusername (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete username attribute");
    return -1;
  }

  if (!PyBool_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The username attribute value must be a bool");
    return -1;
  }

  if (PyObject_IsTrue (value))
  {

    Py_INCREF (value);
    self->user_options->username = 1;

  }
  else
  {

    Py_INCREF (value);
    self->user_options->username = 0;

  }



  return 0;

}

PyDoc_STRVAR(veracrypt_keyfiles__doc__,
"veracrypt_keyfiles\tstr\tKeyfiles used, separate with comma\n\n");

// getter - veracrypt_keyfiles
static PyObject *hashcat_getveracrypt_keyfiles (hashcatObject * self)
{

  if (self->user_options->veracrypt_keyfiles == NULL)
  {
    Py_INCREF (Py_None);
    return Py_None;
  }

  return Py_BuildValue ("s", self->user_options->veracrypt_keyfiles);

}

// setter - veracrypt_keyfiles
static int hashcat_setveracrypt_keyfiles (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete veracrypt_keyfiles attribute");
    return -1;
  }

  if (!PyString_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The veracrypt_keyfiles attribute value must be a string");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->veracrypt_keyfiles = PyString_AsString (value);

  return 0;

}

PyDoc_STRVAR(veracrypt_pim__doc__,
"veracrypt_pim\tint\tVeraCrypt personal iterations multiplier\n\n");

// getter - veracrypt_pim
static PyObject *hashcat_getveracrypt_pim (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->veracrypt_pim);

}

// setter - veracrypt_pim
static int hashcat_setveracrypt_pim (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete veracrypt_pim attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The veracrypt_pim attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->veracrypt_pim = PyInt_AsLong (value);

  return 0;

}



PyDoc_STRVAR(workload_profile__doc__,
"workload_profile\tint\tEnable a specific workload profile, see pool below\n\n\
REFERENCE:\n\
\t            | Performance | Runtime | Power Consumption | Desktop Impact\n\
\t------------+-------------+---------+-------------------+---------------\n\
\t1           | Low         |   2 ms  | Low               | Minimal\n\
\t2           | Default     |  12 ms  | Economic          | Noticeable\n\
\t3           | High        |  96 ms  | High              | Unresponsive\n\
\t4           | Nightmare   | 480 ms  | Insane            | Headless\n\n");

// getter - workload_profile
static PyObject *hashcat_getworkload_profile (hashcatObject * self)
{

  return Py_BuildValue ("i", self->user_options->workload_profile);

}

// setter - workload_profile
static int hashcat_setworkload_profile (hashcatObject * self, PyObject * value, void *closure)
{

  if (value == NULL)
  {

    PyErr_SetString (PyExc_TypeError, "Cannot delete workload_profile attribute");
    return -1;
  }

  if (!PyInt_Check (value))
  {

    PyErr_SetString (PyExc_TypeError, "The workload_profile attribute value must be a int");
    return -1;
  }

  Py_INCREF (value);
  self->user_options->workload_profile = PyInt_AsLong (value);

  return 0;

}



/* method array */

static PyMethodDef hashcat_methods[] = {
  
  {"event_connect", (PyCFunction) hashcat_event_connect, METH_VARARGS|METH_KEYWORDS, event_connect__doc__},
  {"reset", (PyCFunction) hashcat_reset, METH_NOARGS, reset__doc__},
  {"hashcat_session_execute", (PyCFunction) hashcat_hashcat_session_execute, METH_VARARGS|METH_KEYWORDS, hashcat_session_execute__doc__},
  {"hashcat_session_pause", (PyCFunction) hashcat_hashcat_session_pause, METH_NOARGS, hashcat_session_pause__doc__},
  {"hashcat_session_resume", (PyCFunction) hashcat_hashcat_session_resume, METH_NOARGS, hashcat_session_resume__doc__},
  {"hashcat_session_bypass", (PyCFunction) hashcat_hashcat_session_bypass, METH_NOARGS, hashcat_session_bypass__doc__},
  {"hashcat_session_checkpoint", (PyCFunction) hashcat_hashcat_session_checkpoint, METH_NOARGS, hashcat_session_checkpoint__doc__},
  {"hashcat_session_quit", (PyCFunction) hashcat_hashcat_session_quit, METH_NOARGS, hashcat_session_quit__doc__},
  {"status_get_device_info_cnt", (PyCFunction) hashcat_status_get_device_info_cnt, METH_NOARGS, status_get_device_info_cnt__doc__},
  {"status_get_device_info_active", (PyCFunction) hashcat_status_get_device_info_active, METH_NOARGS, status_get_device_info_active__doc__},
  {"status_get_skipped_dev", (PyCFunction) hashcat_status_get_skipped_dev, METH_VARARGS, status_get_skipped_dev__doc__},
  {"status_get_session", (PyCFunction) hashcat_status_get_session, METH_NOARGS, status_get_session__doc__},
  {"status_get_status_string", (PyCFunction) hashcat_status_get_status_string, METH_NOARGS, status_get_status_string__doc__},
  {"status_get_status_number", (PyCFunction) hashcat_status_get_status_number, METH_NOARGS, status_get_status_number__doc__},
  {"status_get_guess_mode", (PyCFunction) hashcat_status_get_guess_mode, METH_NOARGS, status_get_guess_mode__doc__},
  {"status_get_guess_base", (PyCFunction) hashcat_status_get_guess_base, METH_NOARGS, status_get_guess_base__doc__},
  {"status_get_guess_base_offset", (PyCFunction) hashcat_status_get_guess_base_offset, METH_NOARGS, status_get_guess_base_offset__doc__},
  {"status_get_guess_base_count", (PyCFunction) hashcat_status_get_guess_base_count, METH_NOARGS, status_get_guess_base_count__doc__},
  {"status_get_guess_base_percent", (PyCFunction) hashcat_status_get_guess_base_percent, METH_NOARGS, status_get_guess_base_percent__doc__},
  {"status_get_guess_mod", (PyCFunction) hashcat_status_get_guess_mod, METH_NOARGS, status_get_guess_mod__doc__},
  {"status_get_guess_mod_offset", (PyCFunction) hashcat_status_get_guess_mod_offset, METH_NOARGS, status_get_guess_mod_offset__doc__},
  {"status_get_guess_mod_count", (PyCFunction) hashcat_status_get_guess_mod_count, METH_NOARGS, status_get_guess_mod_count__doc__},
  {"status_get_guess_mod_percent", (PyCFunction) hashcat_status_get_guess_mod_percent, METH_NOARGS, status_get_guess_mod_percent__doc__},
  {"status_get_guess_charset", (PyCFunction) hashcat_status_get_guess_charset, METH_NOARGS, status_get_guess_charset__doc__},
  {"status_get_guess_mask_length", (PyCFunction) hashcat_status_get_guess_mask_length, METH_NOARGS, status_get_guess_mask_length__doc__},
  {"status_get_guess_candidates_dev", (PyCFunction) hashcat_status_get_guess_candidates_dev, METH_VARARGS, status_get_guess_candidates_dev__doc__},
  {"status_get_hash_type", (PyCFunction) hashcat_status_get_hash_type, METH_NOARGS, status_get_hash_type__doc__},
  {"status_get_hash_target", (PyCFunction) hashcat_status_get_hash_target, METH_NOARGS, status_get_hash_target__doc__},
  {"status_get_digests_done", (PyCFunction) hashcat_status_get_digests_done, METH_NOARGS, status_get_digests_done__doc__},
  {"status_get_digests_cnt", (PyCFunction) hashcat_status_get_digests_cnt, METH_NOARGS, status_get_digests_cnt__doc__},
  {"status_get_digests_percent", (PyCFunction) hashcat_status_get_digests_percent, METH_NOARGS, status_get_digests_percent__doc__},
  {"status_get_salts_done", (PyCFunction) hashcat_status_get_salts_done, METH_NOARGS, status_get_salts_done__doc__},
  {"status_get_salts_cnt", (PyCFunction) hashcat_status_get_salts_cnt, METH_NOARGS, status_get_salts_cnt__doc__},
  {"status_get_salts_percent", (PyCFunction) hashcat_status_get_salts_percent, METH_NOARGS, status_get_salts_percent__doc__},
  {"status_get_msec_running", (PyCFunction) hashcat_status_get_msec_running, METH_NOARGS, status_get_msec_running__doc__},
  {"status_get_msec_paused", (PyCFunction) hashcat_status_get_msec_paused, METH_NOARGS, status_get_msec_paused__doc__},
  {"status_get_msec_real", (PyCFunction) hashcat_status_get_msec_real, METH_NOARGS, status_get_msec_real__doc__},
  {"status_get_time_started_absolute", (PyCFunction) hashcat_status_get_time_started_absolute, METH_NOARGS, status_get_time_started_absolute__doc__},
  {"status_get_time_started_relative", (PyCFunction) hashcat_status_get_time_started_relative, METH_NOARGS, status_get_time_started_relative__doc__},
  {"status_get_time_estimated_absolute", (PyCFunction) hashcat_status_get_time_estimated_absolute, METH_NOARGS, status_get_time_estimated_absolute__doc__},
  {"status_get_time_estimated_relative", (PyCFunction) hashcat_status_get_time_estimated_relative, METH_NOARGS, status_get_time_estimated_relative__doc__},
  {"status_get_restore_point", (PyCFunction) hashcat_status_get_restore_point, METH_NOARGS, status_get_restore_point__doc__},
  {"status_get_restore_total", (PyCFunction) hashcat_status_get_restore_total, METH_NOARGS, status_get_restore_total__doc__},
  {"status_get_restore_percent", (PyCFunction) hashcat_status_get_restore_percent, METH_NOARGS, status_get_restore_percent__doc__},
  {"status_get_progress_mode", (PyCFunction) hashcat_status_get_progress_mode, METH_NOARGS, status_get_progress_mode__doc__},
  {"status_get_progress_finished_percent", (PyCFunction) hashcat_status_get_progress_finished_percent, METH_NOARGS, status_get_progress_finished_percent__doc__},
  {"status_get_progress_done", (PyCFunction) hashcat_status_get_progress_done, METH_NOARGS, status_get_progress_done__doc__},
  {"status_get_progress_rejected", (PyCFunction) hashcat_status_get_progress_rejected, METH_NOARGS, status_get_progress_rejected__doc__},
  {"status_get_progress_rejected_percent", (PyCFunction) hashcat_status_get_progress_rejected_percent, METH_NOARGS, status_get_progress_rejected_percent__doc__},
  {"status_get_progress_restored", (PyCFunction) hashcat_status_get_progress_restored, METH_NOARGS, status_get_progress_restored__doc__},
  {"status_get_progress_cur", (PyCFunction) hashcat_status_get_progress_cur, METH_NOARGS, status_get_progress_cur__doc__},
  {"status_get_progress_end", (PyCFunction) hashcat_status_get_progress_end, METH_NOARGS, status_get_progress_end__doc__},
  {"status_get_progress_ignore", (PyCFunction) hashcat_status_get_progress_ignore, METH_NOARGS, status_get_progress_ignore__doc__},
  {"status_get_progress_skip", (PyCFunction) hashcat_status_get_progress_skip, METH_NOARGS, status_get_progress_skip__doc__},
  {"status_get_progress_cur_relative_skip", (PyCFunction) hashcat_status_get_progress_cur_relative_skip, METH_NOARGS, status_get_progress_cur_relative_skip__doc__},
  {"status_get_progress_end_relative_skip", (PyCFunction) hashcat_status_get_progress_end_relative_skip, METH_NOARGS, status_get_progress_end_relative_skip__doc__},
  {"status_get_hashes_msec_all", (PyCFunction) hashcat_status_get_hashes_msec_all, METH_NOARGS, status_get_hashes_msec_all__doc__},
  {"status_get_hashes_msec_dev", (PyCFunction) hashcat_status_get_hashes_msec_dev, METH_VARARGS, status_get_hashes_msec_dev__doc__},
  {"status_get_hashes_msec_dev_benchmark", (PyCFunction) hashcat_status_get_hashes_msec_dev_benchmark, METH_VARARGS, status_get_hashes_msec_dev_benchmark__doc__},
  {"status_get_exec_msec_all", (PyCFunction) hashcat_status_get_exec_msec_all, METH_NOARGS, status_get_exec_msec_all__doc__},
  {"status_get_exec_msec_dev", (PyCFunction) hashcat_status_get_exec_msec_dev, METH_VARARGS, status_get_exec_msec_dev__doc__},
  {"status_get_speed_sec_all", (PyCFunction) hashcat_status_get_speed_sec_all, METH_NOARGS, status_get_speed_sec_all__doc__},
  {"status_get_speed_sec_dev", (PyCFunction) hashcat_status_get_speed_sec_dev, METH_VARARGS, status_get_speed_sec_dev__doc__},
  {"status_get_cpt_cur_min", (PyCFunction) hashcat_status_get_cpt_cur_min, METH_NOARGS, status_get_cpt_cur_min__doc__},
  {"status_get_cpt_cur_hour", (PyCFunction) hashcat_status_get_cpt_cur_hour, METH_NOARGS, status_get_cpt_cur_hour__doc__},
  {"status_get_cpt_cur_day", (PyCFunction) hashcat_status_get_cpt_cur_day, METH_NOARGS, status_get_cpt_cur_day__doc__},
  {"status_get_cpt_avg_min", (PyCFunction) hashcat_status_get_cpt_avg_min, METH_NOARGS, status_get_cpt_avg_min__doc__},
  {"status_get_cpt_avg_hour", (PyCFunction) hashcat_status_get_cpt_avg_hour, METH_NOARGS, status_get_cpt_avg_hour__doc__},
  {"status_get_cpt_avg_day", (PyCFunction) hashcat_status_get_cpt_avg_day, METH_NOARGS, status_get_cpt_avg_day__doc__},
  {"status_get_cpt", (PyCFunction) hashcat_status_get_cpt, METH_NOARGS, status_get_cpt__doc__},
  {"status_get_hwmon_dev", (PyCFunction) hashcat_status_get_hwmon_dev, METH_VARARGS, status_get_hwmon_dev__doc__},
  {"status_get_corespeed_dev", (PyCFunction) hashcat_status_get_corespeed_dev, METH_VARARGS, status_get_corespeed_dev__doc__},
  {"status_get_memoryspeed_dev", (PyCFunction) hashcat_status_get_memoryspeed_dev, METH_VARARGS, status_get_memoryspeed_dev__doc__},
  {"status_get_progress_dev", (PyCFunction) hashcat_status_get_progress_dev, METH_VARARGS, status_get_progress_dev__doc__},
  {"status_get_runtime_msec_dev", (PyCFunction) hashcat_status_get_runtime_msec_dev, METH_VARARGS, status_get_runtime_msec_dev__doc__},
  {NULL, NULL, 0, NULL}
};


static PyGetSetDef hashcat_getseters[] = {

  {"hash", (getter) hashcat_gethash, (setter) hashcat_sethash, hash__doc__, NULL},
  {"dict1", (getter) hashcat_getdict1, (setter) hashcat_setdict1, dict1__doc__, NULL},
  {"dict2", (getter) hashcat_getdict2, (setter) hashcat_setdict2, dict2__doc__, NULL},
  {"mask", (getter) hashcat_getmask, (setter) hashcat_setmask, mask__doc__, NULL},
  {"attack_mode", (getter) hashcat_getattack_mode, (setter) hashcat_setattack_mode, attack_mode__doc__, NULL},
  {"benchmark", (getter) hashcat_getbenchmark, (setter) hashcat_setbenchmark, benchmark__doc__, NULL},
  {"bitmap_max", (getter) hashcat_getbitmap_max, (setter) hashcat_setbitmap_max, bitmap_max__doc__, NULL},
  {"bitmap_min", (getter) hashcat_getbitmap_min, (setter) hashcat_setbitmap_min, bitmap_min__doc__, NULL},
  {"cpu_affinity", (getter) hashcat_getcpu_affinity, (setter) hashcat_setcpu_affinity, cpu_affinity__doc__, NULL},
  {"custom_charset_1", (getter) hashcat_getcustom_charset_1, (setter) hashcat_setcustom_charset_1, custom_charset_1__doc__, NULL},
  {"custom_charset_2", (getter) hashcat_getcustom_charset_2, (setter) hashcat_setcustom_charset_2, custom_charset_2__doc__, NULL},
  {"custom_charset_3", (getter) hashcat_getcustom_charset_3, (setter) hashcat_setcustom_charset_3, custom_charset_3__doc__, NULL},
  {"custom_charset_4", (getter) hashcat_getcustom_charset_4, (setter) hashcat_setcustom_charset_4, custom_charset_4__doc__, NULL},
  {"debug_file", (getter) hashcat_getdebug_file, (setter) hashcat_setdebug_file, debug_file__doc__, NULL},
  {"debug_mode", (getter) hashcat_getdebug_mode, (setter) hashcat_setdebug_mode, debug_mode__doc__, NULL},
  {"force", (getter) hashcat_getforce, (setter) hashcat_setforce, force__doc__, NULL},
  {"gpu_temp_abort", (getter) hashcat_getgpu_temp_abort, (setter) hashcat_setgpu_temp_abort, gpu_temp_abort__doc__, NULL},
  {"gpu_temp_disable", (getter) hashcat_getgpu_temp_disable, (setter) hashcat_setgpu_temp_disable, gpu_temp_disable__doc__, NULL},
  {"hash_mode", (getter) hashcat_gethash_mode, (setter) hashcat_sethash_mode, hash_mode__doc__, NULL},
  {"hex_charset", (getter) hashcat_gethex_charset, (setter) hashcat_sethex_charset, hex_charset__doc__, NULL},
  {"hex_salt", (getter) hashcat_gethex_salt, (setter) hashcat_sethex_salt, hex_salt__doc__, NULL},
  {"hex_wordlist", (getter) hashcat_gethex_wordlist, (setter) hashcat_sethex_wordlist, hex_wordlist__doc__, NULL},
  {"increment", (getter) hashcat_getincrement, (setter) hashcat_setincrement, increment__doc__, NULL},
  {"increment_max", (getter) hashcat_getincrement_max, (setter) hashcat_setincrement_max, increment_max__doc__, NULL},
  {"increment_min", (getter) hashcat_getincrement_min, (setter) hashcat_setincrement_min, increment_min__doc__, NULL},
  {"induction_dir", (getter) hashcat_getinduction_dir, (setter) hashcat_setinduction_dir, induction_dir__doc__, NULL},
  {"keep_guessing", (getter) hashcat_getkeep_guessing, (setter) hashcat_setkeep_guessing, keep_guessing__doc__, NULL},
  {"kernel_accel", (getter) hashcat_getkernel_accel, (setter) hashcat_setkernel_accel, kernel_accel__doc__, NULL},
  {"kernel_loops", (getter) hashcat_getkernel_loops, (setter) hashcat_setkernel_loops, kernel_loops__doc__, NULL},
  {"keyspace", (getter) hashcat_getkeyspace, (setter) hashcat_setkeyspace, keyspace__doc__, NULL},
  {"left", (getter) hashcat_getleft, (setter) hashcat_setleft, left__doc__, NULL},
  {"limit", (getter) hashcat_getlimit, (setter) hashcat_setlimit, limit__doc__, NULL},
  {"logfile_disable", (getter) hashcat_getlogfile_disable, (setter) hashcat_setlogfile_disable, logfile_disable__doc__, NULL},
  {"loopback", (getter) hashcat_getloopback, (setter) hashcat_setloopback, loopback__doc__, NULL},
  {"machine_readable", (getter) hashcat_getmachine_readable, (setter) hashcat_setmachine_readable, machine_readable__doc__, NULL},
  {"markov_classic", (getter) hashcat_getmarkov_classic, (setter) hashcat_setmarkov_classic, markov_classic__doc__, NULL},
  {"markov_disable", (getter) hashcat_getmarkov_disable, (setter) hashcat_setmarkov_disable, markov_disable__doc__, NULL},
  {"markov_hcstat", (getter) hashcat_getmarkov_hcstat, (setter) hashcat_setmarkov_hcstat, markov_hcstat__doc__, NULL},
  {"markov_threshold", (getter) hashcat_getmarkov_threshold, (setter) hashcat_setmarkov_threshold, markov_threshold__doc__, NULL},
  {"nvidia_spin_damp", (getter) hashcat_getnvidia_spin_damp, (setter) hashcat_setnvidia_spin_damp, nvidia_spin_damp__doc__, NULL},
  {"opencl_device_types", (getter) hashcat_getopencl_device_types, (setter) hashcat_setopencl_device_types, opencl_device_types__doc__, NULL},
  {"opencl_devices", (getter) hashcat_getopencl_devices, (setter) hashcat_setopencl_devices, opencl_devices__doc__, NULL},
  {"opencl_info", (getter) hashcat_getopencl_info, (setter) hashcat_setopencl_info, opencl_info__doc__, NULL},
  {"opencl_platforms", (getter) hashcat_getopencl_platforms, (setter) hashcat_setopencl_platforms, opencl_platforms__doc__, NULL},
  {"opencl_vector_width", (getter) hashcat_getopencl_vector_width, (setter) hashcat_setopencl_vector_width, opencl_vector_width__doc__, NULL},
  {"outfile", (getter) hashcat_getoutfile, (setter) hashcat_setoutfile, outfile__doc__, NULL},
  {"outfile_autohex", (getter) hashcat_getoutfile_autohex, (setter) hashcat_setoutfile_autohex, outfile_autohex__doc__, NULL},
  {"outfile_check_dir", (getter) hashcat_getoutfile_check_dir, (setter) hashcat_setoutfile_check_dir, outfile_check_dir__doc__, NULL},
  {"outfile_check_timer", (getter) hashcat_getoutfile_check_timer, (setter) hashcat_setoutfile_check_timer, outfile_check_timer__doc__, NULL},
  {"outfile_format", (getter) hashcat_getoutfile_format, (setter) hashcat_setoutfile_format, outfile_format__doc__, NULL},
  {"potfile_disable", (getter) hashcat_getpotfile_disable, (setter) hashcat_setpotfile_disable, potfile_disable__doc__, NULL},
  {"potfile_path", (getter) hashcat_getpotfile_path, (setter) hashcat_setpotfile_path, potfile_path__doc__, NULL},
  {"quiet", (getter) hashcat_getquiet, (setter) hashcat_setquiet, quiet__doc__, NULL},
  {"remove", (getter) hashcat_getremove, (setter) hashcat_setremove, remove__doc__, NULL},
  {"remove_timer", (getter) hashcat_getremove_timer, (setter) hashcat_setremove_timer, remove_timer__doc__, NULL},
  {"restore", (getter) hashcat_getrestore, (setter) hashcat_setrestore, restore__doc__, NULL},
  {"restore_disable", (getter) hashcat_getrestore_disable, (setter) hashcat_setrestore_disable, restore_disable__doc__, NULL},
  {"restore_file_path", (getter) hashcat_getrestore_file_path, (setter) hashcat_setrestore_file_path, restore_file_path__doc__, NULL},
  {"restore_timer", (getter) hashcat_getrestore_timer, (setter) hashcat_setrestore_timer, restore_timer__doc__, NULL},
  {"rp_gen", (getter) hashcat_getrp_gen, (setter) hashcat_setrp_gen, rp_gen__doc__, NULL},
  {"rp_gen_func_max", (getter) hashcat_getrp_gen_func_max, (setter) hashcat_setrp_gen_func_max, rp_gen_func_max__doc__, NULL},
  {"rp_gen_func_min", (getter) hashcat_getrp_gen_func_min, (setter) hashcat_setrp_gen_func_min, rp_gen_func_min__doc__, NULL},
  {"rp_gen_seed", (getter) hashcat_getrp_gen_seed, (setter) hashcat_setrp_gen_seed, rp_gen_seed__doc__, NULL},
  {"rule_buf_l", (getter) hashcat_getrule_buf_l, (setter) hashcat_setrule_buf_l, rule_buf_l__doc__, NULL},
  {"rule_buf_r", (getter) hashcat_getrule_buf_r, (setter) hashcat_setrule_buf_r, rule_buf_r__doc__, NULL},
  {"runtime", (getter) hashcat_getruntime, (setter) hashcat_setruntime, runtime__doc__, NULL},
  {"scrypt_tmto", (getter) hashcat_getscrypt_tmto, (setter) hashcat_setscrypt_tmto, scrypt_tmto__doc__, NULL},
  {"segment_size", (getter) hashcat_getsegment_size, (setter) hashcat_setsegment_size, segment_size__doc__, NULL},
  {"separator", (getter) hashcat_getseparator, (setter) hashcat_setseparator, separator__doc__, NULL},
  {"session", (getter) hashcat_getsession, (setter) hashcat_setsession, session__doc__, NULL},
  {"show", (getter) hashcat_getshow, (setter) hashcat_setshow, show__doc__, NULL},
  {"skip", (getter) hashcat_getskip, (setter) hashcat_setskip, skip__doc__, NULL},
  {"speed_only", (getter) hashcat_getspeed_only, (setter) hashcat_setspeed_only, speed_only__doc__, NULL},
  {"progress_only", (getter) hashcat_getprogress_only, (setter) hashcat_setprogress_only, progress_only__doc__, NULL},
  // {"stdout_flag", (getter)hashcat_getstdout_flag, (setter)hashcat_setstdout_flag, stdout_flag__doc__, NULL },
  {"truecrypt_keyfiles", (getter) hashcat_gettruecrypt_keyfiles, (setter) hashcat_settruecrypt_keyfiles, truecrypt_keyfiles__doc__, NULL},
  {"username", (getter) hashcat_getusername, (setter) hashcat_setusername, username__doc__, NULL},
  {"veracrypt_keyfiles", (getter) hashcat_getveracrypt_keyfiles, (setter) hashcat_setveracrypt_keyfiles, veracrypt_keyfiles__doc__, NULL},
  {"veracrypt_pim", (getter) hashcat_getveracrypt_pim, (setter) hashcat_setveracrypt_pim, veracrypt_pim__doc__, NULL},
  {"workload_profile", (getter) hashcat_getworkload_profile, (setter) hashcat_setworkload_profile, workload_profile__doc__, NULL},
  {NULL}

};


static PyMemberDef hashcat_members[] = {

  {"rules", T_OBJECT, offsetof (hashcatObject, rp_files), 0, rules__doc__},
  {"event_types", T_OBJECT, offsetof (hashcatObject, event_types), 0, event_types__doc__},
  {NULL}
};

static PyTypeObject hashcat_Type = {
  PyObject_HEAD_INIT (NULL) 0,  /* ob_size */
  "pyhashcat.hashcat",          /* tp_name */
  sizeof (hashcatObject),       /* tp_basicsize */
  0,                            /* tp_itemsize */
  (destructor) hashcat_dealloc, /* tp_dealloc */
  0,                            /* tp_print */
  0,                            /* tp_getattr */
  0,                            /* tp_setattr */
  0,                            /* tp_compare */
  0,                            /* tp_repr */
  0,                            /* tp_as_number */
  0,                            /* tp_as_sequence */
  0,                            /* tp_as_mapping */
  0,                            /* tp_hash */
  0,                            /* tp_call */
  0,                            /* tp_str */
  0,                            /* tp_getattro */
  0,                            /* tp_setattro */
  0,                            /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
  "Python bindings for hashcat",  /* tp_doc */
  0,                            /* tp_traverse */
  0,                            /* tp_clear */
  0,                            /* tp_richcompare */
  0,                            /* tp_weaklistoffset */
  0,                            /* tp_iter */
  0,                            /* tp_iternext */
  hashcat_methods,              /* tp_methods */
  hashcat_members,              /* tp_members */
  hashcat_getseters,            /* tp_getset */
  0,                            /* tp_base */
  0,                            /* tp_dict */
  0,                            /* tp_descr_get */
  0,                            /* tp_descr_set */
  0,                            /* tp_dictoffset */
  0,                            /* tp_init */
  0,                            /* tp_alloc */
  hashcat_new,                  /* tp_new */
};

/* module init */

PyMODINIT_FUNC initpyhashcat (void)
{

  PyObject *m;

  if(!PyEval_ThreadsInitialized())
  {
    PyEval_InitThreads();
  }

  if (PyType_Ready (&hashcat_Type) < 0)
    return;

  m = Py_InitModule3 ("pyhashcat", NULL, "Python Bindings for hashcat");

  if (m == NULL)
    return;

  if (ErrorObject == NULL)
  {

    ErrorObject = PyErr_NewException ("hashcat.error", NULL, NULL);
    if (ErrorObject == NULL)
      return;
  }

  Py_INCREF (ErrorObject);
  PyModule_AddObject (m, "error", ErrorObject);

  if (PyType_Ready (&hashcat_Type) < 0)
    return;

  PyModule_AddObject (m, "Hashcat", (PyObject *) & hashcat_Type);


}
