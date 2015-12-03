/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package fi.okm.mpass.shibboleth.attribute.resolver.data;

import java.io.InputStreamReader;
import java.io.Reader;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.google.gson.Gson;

/**
 * Unit testing for {@link UserDTO} using Gson.
 */
public class UserDTOTest {

    /**
     * Tests parsing of a single user data transfer object without roles nor attributes.
     */
    @Test
    public void testNoRolesNoAttributes() {
        UserDTO user = getUser("user-0role-0attr.json");
        Assert.assertEquals(user.getUsername(), "OID1");
        Assert.assertEquals(user.getFirstName(), "John");
        Assert.assertEquals(user.getLastName(), "Doe");
        Assert.assertNull(user.getRoles());
        Assert.assertNull(user.getAttributes());
    }
    
    /**
     * Tests parsing of a single user data transfer object with one role and one attribute.
     */
    @Test
    public void testOneRoleOneAttribute() {
        UserDTO user = getUser("user-1role-1attr.json");
        Assert.assertEquals(user.getUsername(), "OID1");
        Assert.assertEquals(user.getFirstName(), "John");
        Assert.assertEquals(user.getLastName(), "Doe");
        Assert.assertEquals(user.getRoles().length, 1);
        Assert.assertEquals(user.getRoles()[0].getRole(), "teacher");
        Assert.assertEquals(user.getRoles()[0].getSchool(), "12345");
        Assert.assertEquals(user.getRoles()[0].getGroup(), "7C");
        Assert.assertEquals(user.getRoles()[0].getMunicipality(), "Great City");
        Assert.assertEquals(user.getAttributes().length, 1);
        Assert.assertEquals(user.getAttributes()[0].getName(), "google");
        Assert.assertEquals(user.getAttributes()[0].getValue(), "11XxjGZOeAyNqwTdq0Xec9ydDhYoq5CHrTQXHHSfGWM=");
    }

    /**
     * Tests parsing of a single user data transfer object with two roles and two attributes.
     */
    @Test
    public void testTwoRoleTwoAttribute() {
        UserDTO user = getUser("user-2role-2attr.json");
        Assert.assertEquals(user.getUsername(), "OID1");
        Assert.assertEquals(user.getFirstName(), "John");
        Assert.assertEquals(user.getLastName(), "Doe");
        Assert.assertEquals(user.getRoles().length, 2);
        Assert.assertEquals(user.getRoles()[0].getRole(), "teacher");
        Assert.assertEquals(user.getRoles()[0].getSchool(), "12345");
        Assert.assertEquals(user.getRoles()[0].getGroup(), "7C");
        Assert.assertEquals(user.getRoles()[0].getMunicipality(), "Great City");
        Assert.assertEquals(user.getRoles()[1].getRole(), "teacher");
        Assert.assertEquals(user.getRoles()[1].getSchool(), "23456");
        Assert.assertEquals(user.getRoles()[1].getGroup(), "9B");
        Assert.assertEquals(user.getRoles()[1].getMunicipality(), "Rival City");
        Assert.assertEquals(user.getAttributes().length, 2);
        Assert.assertEquals(user.getAttributes()[0].getName(), "google");
        Assert.assertEquals(user.getAttributes()[0].getValue(), "11XxjGZOeAyNqwTdq0Xec9ydDhYoq5CHrTQXHHSfGWM=");
        Assert.assertEquals(user.getAttributes()[1].getName(), "twitter");
        Assert.assertEquals(user.getAttributes()[1].getValue(), "88XxjGZOeAyNqwTdq0Xec9ydDhYoq5CHrTQXHHSfGWM=");
    }

    /**
     * Parses a user object from the given class path resource.
     * 
     * @param classResource The resource containing user JSON.
     * @return The user object.
     */
    protected UserDTO getUser(String classResource) {
        Gson gson = new Gson();
        Reader reader = new InputStreamReader(this.getClass().getResourceAsStream(classResource));
        return gson.fromJson(reader, UserDTO.class);
    }
}