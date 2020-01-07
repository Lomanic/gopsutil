// +build darwin
// +build amd64

package disk

const (
	MfsNameLen = 15 /* length of fs type name, not inc. nul */
	MNameLen   = 90 /* length of buffer for returned name */

	MFSTYPENAMELEN = 16 /* length of fs type name including null */
	MAXPATHLEN     = 1024
	MNAMELEN       = MAXPATHLEN
)

type uid_t int32

// sys/mount.h
const (
	MntSuidDir      = 0x00100000 /* special handling of SUID on dirs */
	MntSoftDep      = 0x00200000 /* soft updates being done */
	MntNoSymFollow  = 0x00400000 /* do not follow symlinks */
	MntGEOMJournal  = 0x02000000 /* GEOM journal support enabled */
	MntACLs         = 0x08000000 /* ACL support enabled */
	MntClusterRead  = 0x40000000 /* disable cluster read */
	MntClusterWrite = 0x80000000 /* disable cluster write */
	MntNFS4ACLs     = 0x00000010
)
