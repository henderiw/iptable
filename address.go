package table

import (
	"k8s.io/apimachinery/pkg/labels"
)

type IPAddress struct {
	labels labels.Set
}

func (r IPAddress) Equal(a2 IPAddress) bool {
	return labels.Equals(r.labels, a2.labels)
}

func (r IPAddress) String() string {
	return r.labels.String()
}

func (r IPAddress) Labels() labels.Set {
	return r.labels
}

// satisfy the k8s labels.Label interface
func (r IPAddress) Get(label string) string {
	return r.labels.Get(label)
}

// satisfy the k8s labels.Label interface
func (r IPAddress) Has(label string) bool {
	return r.labels.Has(label)
}
