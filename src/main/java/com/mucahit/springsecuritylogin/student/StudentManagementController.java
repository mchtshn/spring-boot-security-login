package com.mucahit.springsecuritylogin.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "mucahit"),
            new Student(2, "ahmet"),
            new Student(3, "mehmet")
    );

    @GetMapping
    //@PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMINTRAINEE')")
    public List<Student> getAllStudents() {
        System.out.println("ALL STUDENTS");
        return STUDENTS;
    }

    @PostMapping
    //@PreAuthorize("hasAuthority('course:write')")
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println("REGISTERED NEW STUDENT");
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    //@PreAuthorize("hasAuthority('course:write')")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println("DELETED STUDENT");
        System.out.println("Deleted student "+studentId);
    }

    @PutMapping(path = "{studentId}")
    //@PreAuthorize("hasAuthority('course:write')")
    public void updateStudent(@PathVariable("studentId") Integer studentId,@RequestBody Student student) {
        System.out.println("UPDATED STUDENT");
        System.out.println(String.format("%s %s",studentId,student));
    }
}
