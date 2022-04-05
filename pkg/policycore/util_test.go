/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package policycore

import "testing"

func TestMatches(t *testing.T) {
	type test struct {
		name    string
		sel     NamespaceSelector
		wantLen int
	}

	testInput := []string{"foo", "bar", "baz", "boo", "default", "kube-one", "kube-two", "kube-three"}

	tests := []test{
		{
			name:    "include all",
			sel:     NamespaceSelector{Include: []NonEmptyString{"*"}, Exclude: []NonEmptyString{}},
			wantLen: len(testInput),
		}, {
			name:    "exclude all",
			sel:     NamespaceSelector{Include: []NonEmptyString{"*"}, Exclude: []NonEmptyString{"*"}},
			wantLen: 0,
		}, {
			name:    "include *a*",
			sel:     NamespaceSelector{Include: []NonEmptyString{"*a*"}, Exclude: []NonEmptyString{}},
			wantLen: 3,
		}, {
			name:    "include f*",
			sel:     NamespaceSelector{Include: []NonEmptyString{"f*"}, Exclude: []NonEmptyString{}},
			wantLen: 1,
		}, {
			name:    "include *oo",
			sel:     NamespaceSelector{Include: []NonEmptyString{"*oo"}, Exclude: []NonEmptyString{}},
			wantLen: 2,
		}, {
			name:    "exclude kube*",
			sel:     NamespaceSelector{Include: []NonEmptyString{"*"}, Exclude: []NonEmptyString{"kube*"}},
			wantLen: 5,
		}, {
			name:    "include specifics",
			sel:     NamespaceSelector{Include: []NonEmptyString{"foo", "bar", "default"}, Exclude: []NonEmptyString{}},
			wantLen: 3,
		}, {
			name:    "include specifics, exclude items that aren't included",
			sel:     NamespaceSelector{Include: []NonEmptyString{"foo", "bar", "default"}, Exclude: []NonEmptyString{"kube-*"}},
			wantLen: 3,
		}, {
			name:    "include specifics, exclude one of them",
			sel:     NamespaceSelector{Include: []NonEmptyString{"foo", "bar", "default"}, Exclude: []NonEmptyString{"default"}},
			wantLen: 2,
		}, {
			name:    "exclude specifics",
			sel:     NamespaceSelector{Include: []NonEmptyString{"*"}, Exclude: []NonEmptyString{"kube-two", "default"}},
			wantLen: len(testInput) - 2,
		}, {
			name:    "include ??? (three letters only)",
			sel:     NamespaceSelector{Include: []NonEmptyString{"???"}, Exclude: []NonEmptyString{}},
			wantLen: 4,
		}, {
			name:    "include ??? (three letters only), exclude foo",
			sel:     NamespaceSelector{Include: []NonEmptyString{"???"}, Exclude: []NonEmptyString{"foo"}},
			wantLen: 3,
		},
	}

	for _, tc := range tests {
		got, err := tc.sel.matches(testInput)
		if err != nil {
			t.Error("Unexpected error", err)
		}
		if len(got) != tc.wantLen {
			t.Errorf("test '%v' expected len: %v, got: %v, matches: %v", tc.name, tc.wantLen, len(got), got)
		}
	}
}
